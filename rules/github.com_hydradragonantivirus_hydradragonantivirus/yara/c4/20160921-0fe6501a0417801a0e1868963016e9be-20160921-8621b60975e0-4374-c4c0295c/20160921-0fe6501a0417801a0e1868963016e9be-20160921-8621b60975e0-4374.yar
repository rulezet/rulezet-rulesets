rule _20160921_0fe6501a0417801a0e1868963016e9be_20160921_8621b60975e0_4374 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash3       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash4       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash5       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash6       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "on f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s2 = "\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function " ascii
    $s3 = "0(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";}" ascii
    $s4 = "return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})()" ascii
    $s5 = "ction f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}