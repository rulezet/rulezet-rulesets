rule TTP_XOR_QUAD_CurrentVersionRun_6f0c {
  strings:
    $key_6f0c = { 3c 63 [2] 18 6d [2] 33 41 [2] 1d 63 [2] 09 78 [2] 06 62 [2] 18 7f [2] 1a 7e [2] 01 78 [2] 1d 7f [2] 01 50 }

  condition:
    any of them
}