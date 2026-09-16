rule TTP_XOR_QUAD_CurrentVersionRun_171a {
  strings:
    $key_171a = { 44 75 [2] 60 7b [2] 4b 57 [2] 65 75 [2] 71 6e [2] 7e 74 [2] 60 69 [2] 62 68 [2] 79 6e [2] 65 69 [2] 79 46 }

  condition:
    any of them
}