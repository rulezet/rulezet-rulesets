rule TTP_XOR_QUAD_CurrentVersionRun_2639 {
  strings:
    $key_2639 = { 75 56 [2] 51 58 [2] 7a 74 [2] 54 56 [2] 40 4d [2] 4f 57 [2] 51 4a [2] 53 4b [2] 48 4d [2] 54 4a [2] 48 65 }

  condition:
    any of them
}