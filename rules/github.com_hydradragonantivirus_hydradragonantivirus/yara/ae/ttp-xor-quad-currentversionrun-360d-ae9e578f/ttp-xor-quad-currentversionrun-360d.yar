rule TTP_XOR_QUAD_CurrentVersionRun_360d {
  strings:
    $key_360d = { 65 62 [2] 41 6c [2] 6a 40 [2] 44 62 [2] 50 79 [2] 5f 63 [2] 41 7e [2] 43 7f [2] 58 79 [2] 44 7e [2] 58 51 }

  condition:
    any of them
}