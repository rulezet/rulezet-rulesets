rule TTP_XOR_QUAD_CurrentVersionRun_360c {
  strings:
    $key_360c = { 65 63 [2] 41 6d [2] 6a 41 [2] 44 63 [2] 50 78 [2] 5f 62 [2] 41 7f [2] 43 7e [2] 58 78 [2] 44 7f [2] 58 50 }

  condition:
    any of them
}