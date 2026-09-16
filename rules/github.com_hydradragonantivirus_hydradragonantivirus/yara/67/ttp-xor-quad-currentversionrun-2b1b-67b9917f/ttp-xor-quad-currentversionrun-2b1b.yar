rule TTP_XOR_QUAD_CurrentVersionRun_2b1b {
  strings:
    $key_2b1b = { 78 74 [2] 5c 7a [2] 77 56 [2] 59 74 [2] 4d 6f [2] 42 75 [2] 5c 68 [2] 5e 69 [2] 45 6f [2] 59 68 [2] 45 47 }

  condition:
    any of them
}