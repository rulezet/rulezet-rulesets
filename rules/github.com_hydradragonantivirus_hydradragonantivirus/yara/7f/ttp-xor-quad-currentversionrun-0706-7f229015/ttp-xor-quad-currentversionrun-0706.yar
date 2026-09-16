rule TTP_XOR_QUAD_CurrentVersionRun_0706 {
  strings:
    $key_0706 = { 54 69 [2] 70 67 [2] 5b 4b [2] 75 69 [2] 61 72 [2] 6e 68 [2] 70 75 [2] 72 74 [2] 69 72 [2] 75 75 [2] 69 5a }

  condition:
    any of them
}