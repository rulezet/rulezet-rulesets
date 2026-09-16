rule TTP_XOR_QUAD_CurrentVersionRun_e248 {
  strings:
    $key_e248 = { b1 27 [2] 95 29 [2] be 05 [2] 90 27 [2] 84 3c [2] 8b 26 [2] 95 3b [2] 97 3a [2] 8c 3c [2] 90 3b [2] 8c 14 }

  condition:
    any of them
}