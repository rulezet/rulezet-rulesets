rule TTP_XOR_QUAD_CurrentVersionRun_2138 {
  strings:
    $key_2138 = { 72 57 [2] 56 59 [2] 7d 75 [2] 53 57 [2] 47 4c [2] 48 56 [2] 56 4b [2] 54 4a [2] 4f 4c [2] 53 4b [2] 4f 64 }

  condition:
    any of them
}