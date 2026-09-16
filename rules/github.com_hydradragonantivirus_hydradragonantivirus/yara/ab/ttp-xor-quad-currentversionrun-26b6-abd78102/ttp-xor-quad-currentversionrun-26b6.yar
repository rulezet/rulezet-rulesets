rule TTP_XOR_QUAD_CurrentVersionRun_26b6 {
  strings:
    $key_26b6 = { 75 d9 [2] 51 d7 [2] 7a fb [2] 54 d9 [2] 40 c2 [2] 4f d8 [2] 51 c5 [2] 53 c4 [2] 48 c2 [2] 54 c5 [2] 48 ea }

  condition:
    any of them
}