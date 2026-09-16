rule TTP_XOR_QUAD_CurrentVersionRun_3c4a {
  strings:
    $key_3c4a = { 6f 25 [2] 4b 2b [2] 60 07 [2] 4e 25 [2] 5a 3e [2] 55 24 [2] 4b 39 [2] 49 38 [2] 52 3e [2] 4e 39 [2] 52 16 }

  condition:
    any of them
}