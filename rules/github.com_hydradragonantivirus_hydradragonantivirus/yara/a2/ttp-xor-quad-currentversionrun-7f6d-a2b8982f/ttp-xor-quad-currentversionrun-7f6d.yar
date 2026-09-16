rule TTP_XOR_QUAD_CurrentVersionRun_7f6d {
  strings:
    $key_7f6d = { 2c 02 [2] 08 0c [2] 23 20 [2] 0d 02 [2] 19 19 [2] 16 03 [2] 08 1e [2] 0a 1f [2] 11 19 [2] 0d 1e [2] 11 31 }

  condition:
    any of them
}