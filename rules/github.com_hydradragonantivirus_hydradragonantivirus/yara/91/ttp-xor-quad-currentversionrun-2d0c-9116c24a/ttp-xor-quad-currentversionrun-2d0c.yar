rule TTP_XOR_QUAD_CurrentVersionRun_2d0c {
  strings:
    $key_2d0c = { 7e 63 [2] 5a 6d [2] 71 41 [2] 5f 63 [2] 4b 78 [2] 44 62 [2] 5a 7f [2] 58 7e [2] 43 78 [2] 5f 7f [2] 43 50 }

  condition:
    any of them
}