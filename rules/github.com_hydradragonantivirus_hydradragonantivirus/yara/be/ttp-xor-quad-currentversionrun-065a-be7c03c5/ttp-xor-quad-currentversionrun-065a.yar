rule TTP_XOR_QUAD_CurrentVersionRun_065a {
  strings:
    $key_065a = { 55 35 [2] 71 3b [2] 5a 17 [2] 74 35 [2] 60 2e [2] 6f 34 [2] 71 29 [2] 73 28 [2] 68 2e [2] 74 29 [2] 68 06 }

  condition:
    any of them
}