rule TTP_XOR_QUAD_CurrentVersionRun_f974 {
  strings:
    $key_f974 = { aa 1b [2] 8e 15 [2] a5 39 [2] 8b 1b [2] 9f 00 [2] 90 1a [2] 8e 07 [2] 8c 06 [2] 97 00 [2] 8b 07 [2] 97 28 }

  condition:
    any of them
}