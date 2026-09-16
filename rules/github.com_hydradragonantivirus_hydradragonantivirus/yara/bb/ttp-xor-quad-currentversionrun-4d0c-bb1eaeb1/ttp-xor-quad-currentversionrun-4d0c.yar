rule TTP_XOR_QUAD_CurrentVersionRun_4d0c {
  strings:
    $key_4d0c = { 1e 63 [2] 3a 6d [2] 11 41 [2] 3f 63 [2] 2b 78 [2] 24 62 [2] 3a 7f [2] 38 7e [2] 23 78 [2] 3f 7f [2] 23 50 }

  condition:
    any of them
}