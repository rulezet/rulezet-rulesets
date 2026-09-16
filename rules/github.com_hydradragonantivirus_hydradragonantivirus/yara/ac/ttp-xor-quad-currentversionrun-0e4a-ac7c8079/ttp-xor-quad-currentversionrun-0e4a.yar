rule TTP_XOR_QUAD_CurrentVersionRun_0e4a {
  strings:
    $key_0e4a = { 5d 25 [2] 79 2b [2] 52 07 [2] 7c 25 [2] 68 3e [2] 67 24 [2] 79 39 [2] 7b 38 [2] 60 3e [2] 7c 39 [2] 60 16 }

  condition:
    any of them
}