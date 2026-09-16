rule TTP_XOR_QUAD_CurrentVersionRun_680c {
  strings:
    $key_680c = { 3b 63 [2] 1f 6d [2] 34 41 [2] 1a 63 [2] 0e 78 [2] 01 62 [2] 1f 7f [2] 1d 7e [2] 06 78 [2] 1a 7f [2] 06 50 }

  condition:
    any of them
}