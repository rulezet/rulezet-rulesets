rule TTP_XOR_QUAD_CurrentVersionRun_456a {
  strings:
    $key_456a = { 16 05 [2] 32 0b [2] 19 27 [2] 37 05 [2] 23 1e [2] 2c 04 [2] 32 19 [2] 30 18 [2] 2b 1e [2] 37 19 [2] 2b 36 }

  condition:
    any of them
}