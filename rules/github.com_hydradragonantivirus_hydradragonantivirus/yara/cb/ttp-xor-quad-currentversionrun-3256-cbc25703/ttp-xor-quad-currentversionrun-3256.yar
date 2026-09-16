rule TTP_XOR_QUAD_CurrentVersionRun_3256 {
  strings:
    $key_3256 = { 61 39 [2] 45 37 [2] 6e 1b [2] 40 39 [2] 54 22 [2] 5b 38 [2] 45 25 [2] 47 24 [2] 5c 22 [2] 40 25 [2] 5c 0a }

  condition:
    any of them
}