rule TTP_XOR_QUAD_CurrentVersionRun_7c08 {
  strings:
    $key_7c08 = { 2f 67 [2] 0b 69 [2] 20 45 [2] 0e 67 [2] 1a 7c [2] 15 66 [2] 0b 7b [2] 09 7a [2] 12 7c [2] 0e 7b [2] 12 54 }

  condition:
    any of them
}