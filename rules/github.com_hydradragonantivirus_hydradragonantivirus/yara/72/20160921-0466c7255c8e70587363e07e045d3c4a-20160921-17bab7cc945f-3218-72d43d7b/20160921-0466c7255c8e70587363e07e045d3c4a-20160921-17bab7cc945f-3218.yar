rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_17bab7cc945f_3218 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_1b3a88384cf704def4ce92e01728a1df.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash3       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"
    hash4       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash5       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "n f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s2 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s3 = "rn \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(f" ascii
    $s4 = "rn \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(f" ascii
    $s5 = "urn \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})()," ascii
    $s6 = "(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}