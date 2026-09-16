rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_08977f7f9e06_4183 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash3       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash4       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash5       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash6       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1 = "urn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})()," ascii
    $s2 = "rn \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(f" ascii
    $s3 = "),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s4 = ",(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){re" ascii
    $s5 = "ion f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}