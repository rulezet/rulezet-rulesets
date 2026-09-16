rule TTP_XOR_QUAD_CurrentVersionRun_e4b3 {
  strings:
    $key_e4b3 = { b7 dc [2] 93 d2 [2] b8 fe [2] 96 dc [2] 82 c7 [2] 8d dd [2] 93 c0 [2] 91 c1 [2] 8a c7 [2] 96 c0 [2] 8a ef }

  condition:
    any of them
}