rule TTP_XOR_QUAD_CurrentVersionRun_34b6 {
  strings:
    $key_34b6 = { 67 d9 [2] 43 d7 [2] 68 fb [2] 46 d9 [2] 52 c2 [2] 5d d8 [2] 43 c5 [2] 41 c4 [2] 5a c2 [2] 46 c5 [2] 5a ea }

  condition:
    any of them
}