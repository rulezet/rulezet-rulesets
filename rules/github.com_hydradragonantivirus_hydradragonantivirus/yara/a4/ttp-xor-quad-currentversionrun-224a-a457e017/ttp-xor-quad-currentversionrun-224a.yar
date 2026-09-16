rule TTP_XOR_QUAD_CurrentVersionRun_224a {
  strings:
    $key_224a = { 71 25 [2] 55 2b [2] 7e 07 [2] 50 25 [2] 44 3e [2] 4b 24 [2] 55 39 [2] 57 38 [2] 4c 3e [2] 50 39 [2] 4c 16 }

  condition:
    any of them
}