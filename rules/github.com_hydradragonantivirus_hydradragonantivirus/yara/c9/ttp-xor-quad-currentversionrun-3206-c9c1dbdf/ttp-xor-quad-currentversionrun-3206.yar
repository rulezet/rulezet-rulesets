rule TTP_XOR_QUAD_CurrentVersionRun_3206 {
  strings:
    $key_3206 = { 61 69 [2] 45 67 [2] 6e 4b [2] 40 69 [2] 54 72 [2] 5b 68 [2] 45 75 [2] 47 74 [2] 5c 72 [2] 40 75 [2] 5c 5a }

  condition:
    any of them
}