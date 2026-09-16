rule TTP_XOR_QUAD_CurrentVersionRun_e264 {
  strings:
    $key_e264 = { b1 0b [2] 95 05 [2] be 29 [2] 90 0b [2] 84 10 [2] 8b 0a [2] 95 17 [2] 97 16 [2] 8c 10 [2] 90 17 [2] 8c 38 }

  condition:
    any of them
}