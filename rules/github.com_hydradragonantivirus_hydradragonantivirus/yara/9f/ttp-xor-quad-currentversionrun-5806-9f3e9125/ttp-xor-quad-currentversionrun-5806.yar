rule TTP_XOR_QUAD_CurrentVersionRun_5806 {
  strings:
    $key_5806 = { 0b 69 [2] 2f 67 [2] 04 4b [2] 2a 69 [2] 3e 72 [2] 31 68 [2] 2f 75 [2] 2d 74 [2] 36 72 [2] 2a 75 [2] 36 5a }

  condition:
    any of them
}