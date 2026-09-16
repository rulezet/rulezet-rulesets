rule TTP_XOR_QUAD_CurrentVersionRun_14b6 {
  strings:
    $key_14b6 = { 47 d9 [2] 63 d7 [2] 48 fb [2] 66 d9 [2] 72 c2 [2] 7d d8 [2] 63 c5 [2] 61 c4 [2] 7a c2 [2] 66 c5 [2] 7a ea }

  condition:
    any of them
}