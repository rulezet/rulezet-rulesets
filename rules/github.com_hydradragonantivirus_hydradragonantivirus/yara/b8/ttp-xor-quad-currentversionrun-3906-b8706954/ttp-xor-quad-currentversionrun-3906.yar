rule TTP_XOR_QUAD_CurrentVersionRun_3906 {
  strings:
    $key_3906 = { 6a 69 [2] 4e 67 [2] 65 4b [2] 4b 69 [2] 5f 72 [2] 50 68 [2] 4e 75 [2] 4c 74 [2] 57 72 [2] 4b 75 [2] 57 5a }

  condition:
    any of them
}