rule TTP_XOR_QUAD_CurrentVersionRun_064a {
  strings:
    $key_064a = { 55 25 [2] 71 2b [2] 5a 07 [2] 74 25 [2] 60 3e [2] 6f 24 [2] 71 39 [2] 73 38 [2] 68 3e [2] 74 39 [2] 68 16 }

  condition:
    any of them
}