rule TTP_XOR_QUAD_CurrentVersionRun_b4b3 {
  strings:
    $key_b4b3 = { e7 dc [2] c3 d2 [2] e8 fe [2] c6 dc [2] d2 c7 [2] dd dd [2] c3 c0 [2] c1 c1 [2] da c7 [2] c6 c0 [2] da ef }

  condition:
    any of them
}