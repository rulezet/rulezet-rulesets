rule TTP_XOR_QUAD_CurrentVersionRun_334a {
  strings:
    $key_334a = { 60 25 [2] 44 2b [2] 6f 07 [2] 41 25 [2] 55 3e [2] 5a 24 [2] 44 39 [2] 46 38 [2] 5d 3e [2] 41 39 [2] 5d 16 }

  condition:
    any of them
}