rule TTP_XOR_QUAD_CurrentVersionRun_520c {
  strings:
    $key_520c = { 01 63 [2] 25 6d [2] 0e 41 [2] 20 63 [2] 34 78 [2] 3b 62 [2] 25 7f [2] 27 7e [2] 3c 78 [2] 20 7f [2] 3c 50 }

  condition:
    any of them
}