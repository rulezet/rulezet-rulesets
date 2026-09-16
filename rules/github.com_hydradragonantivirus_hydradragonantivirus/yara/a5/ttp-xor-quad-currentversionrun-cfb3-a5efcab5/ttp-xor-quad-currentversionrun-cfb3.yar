rule TTP_XOR_QUAD_CurrentVersionRun_cfb3 {
  strings:
    $key_cfb3 = { 9c dc [2] b8 d2 [2] 93 fe [2] bd dc [2] a9 c7 [2] a6 dd [2] b8 c0 [2] ba c1 [2] a1 c7 [2] bd c0 [2] a1 ef }

  condition:
    any of them
}