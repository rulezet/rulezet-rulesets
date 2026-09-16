rule TTP_XOR_QUAD_CurrentVersionRun_7f0a {
  strings:
    $key_7f0a = { 2c 65 [2] 08 6b [2] 23 47 [2] 0d 65 [2] 19 7e [2] 16 64 [2] 08 79 [2] 0a 78 [2] 11 7e [2] 0d 79 [2] 11 56 }

  condition:
    any of them
}