rule TTP_XOR_QUAD_CurrentVersionRun_2625 {
  strings:
    $key_2625 = { 75 4a [2] 51 44 [2] 7a 68 [2] 54 4a [2] 40 51 [2] 4f 4b [2] 51 56 [2] 53 57 [2] 48 51 [2] 54 56 [2] 48 79 }

  condition:
    any of them
}