rule TTP_XOR_QUAD_CurrentVersionRun_600c {
  strings:
    $key_600c = { 33 63 [2] 17 6d [2] 3c 41 [2] 12 63 [2] 06 78 [2] 09 62 [2] 17 7f [2] 15 7e [2] 0e 78 [2] 12 7f [2] 0e 50 }

  condition:
    any of them
}