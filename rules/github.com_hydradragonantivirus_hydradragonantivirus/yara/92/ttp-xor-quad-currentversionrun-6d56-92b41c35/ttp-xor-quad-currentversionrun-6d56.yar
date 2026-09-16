rule TTP_XOR_QUAD_CurrentVersionRun_6d56 {
  strings:
    $key_6d56 = { 3e 39 [2] 1a 37 [2] 31 1b [2] 1f 39 [2] 0b 22 [2] 04 38 [2] 1a 25 [2] 18 24 [2] 03 22 [2] 1f 25 [2] 03 0a }

  condition:
    any of them
}