rule TTP_XOR_QUAD_CurrentVersionRun_f654 {
  strings:
    $key_f654 = { a5 3b [2] 81 35 [2] aa 19 [2] 84 3b [2] 90 20 [2] 9f 3a [2] 81 27 [2] 83 26 [2] 98 20 [2] 84 27 [2] 98 08 }

  condition:
    any of them
}