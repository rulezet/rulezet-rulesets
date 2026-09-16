rule _20160921_3a185c9392a67b927e245520858a0afc_20160921_5d475fd55c4e_3657 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_68596411289b2d10a74a19f9fce4a325.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js, 20160922_2bdee31da941689170d6b7da303eeff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash2       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash3       = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"
    hash4       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash5       = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"
    hash6       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash7       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"
    hash8       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"

  strings:
    $s1 = "turn \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s2 = "nction f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){retu" ascii
    $s3 = "urn \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s4 = "return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})()" ascii
    $s5 = "tion f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return" ascii
    $s6 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}