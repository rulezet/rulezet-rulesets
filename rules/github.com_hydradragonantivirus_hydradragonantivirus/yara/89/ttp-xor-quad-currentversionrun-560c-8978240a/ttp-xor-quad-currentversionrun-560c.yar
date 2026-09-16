rule TTP_XOR_QUAD_CurrentVersionRun_560c {
  strings:
    $key_560c = { 05 63 [2] 21 6d [2] 0a 41 [2] 24 63 [2] 30 78 [2] 3f 62 [2] 21 7f [2] 23 7e [2] 38 78 [2] 24 7f [2] 38 50 }

  condition:
    any of them
}