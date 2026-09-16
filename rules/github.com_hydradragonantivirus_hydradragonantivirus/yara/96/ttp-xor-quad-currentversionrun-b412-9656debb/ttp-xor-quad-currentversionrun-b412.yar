rule TTP_XOR_QUAD_CurrentVersionRun_b412 {
  strings:
    $key_b412 = { e7 7d [2] c3 73 [2] e8 5f [2] c6 7d [2] d2 66 [2] dd 7c [2] c3 61 [2] c1 60 [2] da 66 [2] c6 61 [2] da 4e }

  condition:
    any of them
}