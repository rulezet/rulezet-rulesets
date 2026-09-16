rule _20160921_523b4f49bbdc4dd92accd0e402a46bfd_20160921_83dee40cf10d_377 {
  meta:
    description = "datamaliciousorder - from files 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash2       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash3       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1  = "urn \"OUx\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(fu" ascii
    $s2  = "n \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s3  = "n f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s4  = ",(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){re" ascii
    $s5  = "0(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\"" ascii
    $s6  = "n \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s7  = "f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp" ascii
    $s8  = "function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s9  = "(),(function f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(" ascii
    $s10 = "GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s11 = "(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";" ascii
    $s12 = "function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){ret" ascii
    $s13 = "00(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi" ascii
    $s14 = "unction f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s15 = "ion f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s16 = "on f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s17 = "tion f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s18 = "Gn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s19 = "000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh" ascii
    $s20 = "\"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}