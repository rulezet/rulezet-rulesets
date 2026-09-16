rule TTP_XOR_QUAD_CurrentVersionRun_6706 {
  strings:
    $key_6706 = { 34 69 [2] 10 67 [2] 3b 4b [2] 15 69 [2] 01 72 [2] 0e 68 [2] 10 75 [2] 12 74 [2] 09 72 [2] 15 75 [2] 09 5a }

  condition:
    any of them
}