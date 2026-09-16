rule TTP_XOR_QUAD_CurrentVersionRun_1256 {
  strings:
    $key_1256 = { 41 39 [2] 65 37 [2] 4e 1b [2] 60 39 [2] 74 22 [2] 7b 38 [2] 65 25 [2] 67 24 [2] 7c 22 [2] 60 25 [2] 7c 0a }

  condition:
    any of them
}