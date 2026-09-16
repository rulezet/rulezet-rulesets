rule TTP_XOR_QUAD_CurrentVersionRun_4c4a {
  strings:
    $key_4c4a = { 1f 25 [2] 3b 2b [2] 10 07 [2] 3e 25 [2] 2a 3e [2] 25 24 [2] 3b 39 [2] 39 38 [2] 22 3e [2] 3e 39 [2] 22 16 }

  condition:
    any of them
}