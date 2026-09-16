rule TTP_XOR_QUAD_CurrentVersionRun_7c0c {
  strings:
    $key_7c0c = { 2f 63 [2] 0b 6d [2] 20 41 [2] 0e 63 [2] 1a 78 [2] 15 62 [2] 0b 7f [2] 09 7e [2] 12 78 [2] 0e 7f [2] 12 50 }

  condition:
    any of them
}