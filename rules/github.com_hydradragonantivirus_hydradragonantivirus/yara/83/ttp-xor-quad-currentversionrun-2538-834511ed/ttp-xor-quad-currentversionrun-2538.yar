rule TTP_XOR_QUAD_CurrentVersionRun_2538 {
  strings:
    $key_2538 = { 76 57 [2] 52 59 [2] 79 75 [2] 57 57 [2] 43 4c [2] 4c 56 [2] 52 4b [2] 50 4a [2] 4b 4c [2] 57 4b [2] 4b 64 }

  condition:
    any of them
}