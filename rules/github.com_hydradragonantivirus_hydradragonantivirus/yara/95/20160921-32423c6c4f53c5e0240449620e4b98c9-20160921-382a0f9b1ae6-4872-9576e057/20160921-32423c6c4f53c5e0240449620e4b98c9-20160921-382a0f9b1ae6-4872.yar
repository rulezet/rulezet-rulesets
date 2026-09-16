rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_382a0f9b1ae6_4872 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash3       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash4       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash5       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(" ascii
    $s2 = "PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(functio" ascii
    $s3 = "nction f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DNa\";})(),(function f000(){ret" ascii
    $s4 = "ction f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){retur" ascii
    $s5 = ";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}