rule TTP_XOR_QUAD_CurrentVersionRun_5538 {
  strings:
    $key_5538 = { 06 57 [2] 22 59 [2] 09 75 [2] 27 57 [2] 33 4c [2] 3c 56 [2] 22 4b [2] 20 4a [2] 3b 4c [2] 27 4b [2] 3b 64 }

  condition:
    any of them
}