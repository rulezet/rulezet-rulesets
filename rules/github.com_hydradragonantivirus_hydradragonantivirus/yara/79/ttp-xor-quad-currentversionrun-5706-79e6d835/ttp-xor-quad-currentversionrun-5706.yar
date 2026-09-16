rule TTP_XOR_QUAD_CurrentVersionRun_5706 {
  strings:
    $key_5706 = { 04 69 [2] 20 67 [2] 0b 4b [2] 25 69 [2] 31 72 [2] 3e 68 [2] 20 75 [2] 22 74 [2] 39 72 [2] 25 75 [2] 39 5a }

  condition:
    any of them
}