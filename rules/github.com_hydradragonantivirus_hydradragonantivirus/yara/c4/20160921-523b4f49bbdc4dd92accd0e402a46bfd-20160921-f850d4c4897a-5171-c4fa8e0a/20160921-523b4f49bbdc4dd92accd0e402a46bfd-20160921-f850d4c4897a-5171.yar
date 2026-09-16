rule _20160921_523b4f49bbdc4dd92accd0e402a46bfd_20160921_f850d4c4897a_5171 {
  meta:
    description = "datamaliciousorder - from files 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash2       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"
    hash3       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash4       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s2 = "urn \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})()," ascii
    $s3 = "n f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s4 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f" ascii
    $s5 = "on f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}