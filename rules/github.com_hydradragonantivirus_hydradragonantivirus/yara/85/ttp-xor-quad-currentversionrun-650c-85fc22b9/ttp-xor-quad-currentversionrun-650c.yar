rule TTP_XOR_QUAD_CurrentVersionRun_650c {
  strings:
    $key_650c = { 36 63 [2] 12 6d [2] 39 41 [2] 17 63 [2] 03 78 [2] 0c 62 [2] 12 7f [2] 10 7e [2] 0b 78 [2] 17 7f [2] 0b 50 }

  condition:
    any of them
}