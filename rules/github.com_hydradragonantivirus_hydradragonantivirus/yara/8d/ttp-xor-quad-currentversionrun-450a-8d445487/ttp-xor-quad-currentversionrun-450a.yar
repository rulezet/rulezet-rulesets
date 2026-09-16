rule TTP_XOR_QUAD_CurrentVersionRun_450a {
  strings:
    $key_450a = { 16 65 [2] 32 6b [2] 19 47 [2] 37 65 [2] 23 7e [2] 2c 64 [2] 32 79 [2] 30 78 [2] 2b 7e [2] 37 79 [2] 2b 56 }

  condition:
    any of them
}