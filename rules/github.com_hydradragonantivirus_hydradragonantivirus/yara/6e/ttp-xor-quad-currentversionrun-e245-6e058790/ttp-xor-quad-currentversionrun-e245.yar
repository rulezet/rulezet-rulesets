rule TTP_XOR_QUAD_CurrentVersionRun_e245 {
  strings:
    $key_e245 = { b1 2a [2] 95 24 [2] be 08 [2] 90 2a [2] 84 31 [2] 8b 2b [2] 95 36 [2] 97 37 [2] 8c 31 [2] 90 36 [2] 8c 19 }

  condition:
    any of them
}