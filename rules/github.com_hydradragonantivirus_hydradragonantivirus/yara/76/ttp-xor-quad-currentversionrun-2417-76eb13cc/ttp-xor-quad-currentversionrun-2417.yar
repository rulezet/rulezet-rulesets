rule TTP_XOR_QUAD_CurrentVersionRun_2417 {
  strings:
    $key_2417 = { 77 78 [2] 53 76 [2] 78 5a [2] 56 78 [2] 42 63 [2] 4d 79 [2] 53 64 [2] 51 65 [2] 4a 63 [2] 56 64 [2] 4a 4b }

  condition:
    any of them
}