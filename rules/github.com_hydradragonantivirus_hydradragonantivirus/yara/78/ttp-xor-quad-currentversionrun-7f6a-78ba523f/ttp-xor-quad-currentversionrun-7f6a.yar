rule TTP_XOR_QUAD_CurrentVersionRun_7f6a {
  strings:
    $key_7f6a = { 2c 05 [2] 08 0b [2] 23 27 [2] 0d 05 [2] 19 1e [2] 16 04 [2] 08 19 [2] 0a 18 [2] 11 1e [2] 0d 19 [2] 11 36 }

  condition:
    any of them
}