rule TTP_XOR_QUAD_CurrentVersionRun_044a {
  strings:
    $key_044a = { 57 25 [2] 73 2b [2] 58 07 [2] 76 25 [2] 62 3e [2] 6d 24 [2] 73 39 [2] 71 38 [2] 6a 3e [2] 76 39 [2] 6a 16 }

  condition:
    any of them
}