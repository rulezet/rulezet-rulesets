rule TTP_XOR_QUAD_CurrentVersionRun_4956 {
  strings:
    $key_4956 = { 1a 39 [2] 3e 37 [2] 15 1b [2] 3b 39 [2] 2f 22 [2] 20 38 [2] 3e 25 [2] 3c 24 [2] 27 22 [2] 3b 25 [2] 27 0a }

  condition:
    any of them
}