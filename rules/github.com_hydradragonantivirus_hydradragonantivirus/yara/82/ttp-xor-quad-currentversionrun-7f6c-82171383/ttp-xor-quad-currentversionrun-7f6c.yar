rule TTP_XOR_QUAD_CurrentVersionRun_7f6c {
  strings:
    $key_7f6c = { 2c 03 [2] 08 0d [2] 23 21 [2] 0d 03 [2] 19 18 [2] 16 02 [2] 08 1f [2] 0a 1e [2] 11 18 [2] 0d 1f [2] 11 30 }

  condition:
    any of them
}