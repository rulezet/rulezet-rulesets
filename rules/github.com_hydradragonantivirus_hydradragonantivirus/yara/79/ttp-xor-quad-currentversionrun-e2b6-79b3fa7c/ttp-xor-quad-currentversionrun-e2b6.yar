rule TTP_XOR_QUAD_CurrentVersionRun_e2b6 {
  strings:
    $key_e2b6 = { b1 d9 [2] 95 d7 [2] be fb [2] 90 d9 [2] 84 c2 [2] 8b d8 [2] 95 c5 [2] 97 c4 [2] 8c c2 [2] 90 c5 [2] 8c ea }

  condition:
    any of them
}