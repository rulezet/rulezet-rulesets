rule _20160921_3a185c9392a67b927e245520858a0afc_20160921_3a89132c2088_4962 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js, 20160922_2bdee31da941689170d6b7da303eeff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash2       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash3       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash4       = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"
    hash5       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash6       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"
    hash7       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"

  strings:
    $s1 = "n f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s2 = "){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})" ascii
    $s3 = "rn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s4 = "TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(functio" ascii
    $s5 = "unction f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}