rule TTP_XOR_QUAD_CurrentVersionRun_f254 {
  strings:
    $key_f254 = { a1 3b [2] 85 35 [2] ae 19 [2] 80 3b [2] 94 20 [2] 9b 3a [2] 85 27 [2] 87 26 [2] 9c 20 [2] 80 27 [2] 9c 08 }

  condition:
    any of them
}