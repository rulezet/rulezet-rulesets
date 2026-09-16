rule TTP_XOR_QUAD_CurrentVersionRun_6f06 {
  strings:
    $key_6f06 = { 3c 69 [2] 18 67 [2] 33 4b [2] 1d 69 [2] 09 72 [2] 06 68 [2] 18 75 [2] 1a 74 [2] 01 72 [2] 1d 75 [2] 01 5a }

  condition:
    any of them
}