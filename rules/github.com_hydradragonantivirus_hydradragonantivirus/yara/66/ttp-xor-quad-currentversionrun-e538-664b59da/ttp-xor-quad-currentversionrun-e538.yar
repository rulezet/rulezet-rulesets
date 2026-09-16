rule TTP_XOR_QUAD_CurrentVersionRun_e538 {
  strings:
    $key_e538 = { b6 57 [2] 92 59 [2] b9 75 [2] 97 57 [2] 83 4c [2] 8c 56 [2] 92 4b [2] 90 4a [2] 8b 4c [2] 97 4b [2] 8b 64 }

  condition:
    any of them
}