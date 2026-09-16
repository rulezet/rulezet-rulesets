rule TTP_XOR_QUAD_CurrentVersionRun_eab6 {
  strings:
    $key_eab6 = { b9 d9 [2] 9d d7 [2] b6 fb [2] 98 d9 [2] 8c c2 [2] 83 d8 [2] 9d c5 [2] 9f c4 [2] 84 c2 [2] 98 c5 [2] 84 ea }

  condition:
    any of them
}