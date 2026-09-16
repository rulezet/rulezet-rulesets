rule TTP_XOR_QUAD_CurrentVersionRun_2b06 {
  strings:
    $key_2b06 = { 78 69 [2] 5c 67 [2] 77 4b [2] 59 69 [2] 4d 72 [2] 42 68 [2] 5c 75 [2] 5e 74 [2] 45 72 [2] 59 75 [2] 45 5a }

  condition:
    any of them
}