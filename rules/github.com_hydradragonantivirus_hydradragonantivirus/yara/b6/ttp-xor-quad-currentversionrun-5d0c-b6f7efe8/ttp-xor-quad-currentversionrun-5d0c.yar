rule TTP_XOR_QUAD_CurrentVersionRun_5d0c {
  strings:
    $key_5d0c = { 0e 63 [2] 2a 6d [2] 01 41 [2] 2f 63 [2] 3b 78 [2] 34 62 [2] 2a 7f [2] 28 7e [2] 33 78 [2] 2f 7f [2] 33 50 }

  condition:
    any of them
}