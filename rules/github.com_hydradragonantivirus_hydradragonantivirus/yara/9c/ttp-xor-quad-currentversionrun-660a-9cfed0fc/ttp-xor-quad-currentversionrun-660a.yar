rule TTP_XOR_QUAD_CurrentVersionRun_660a {
  strings:
    $key_660a = { 35 65 [2] 11 6b [2] 3a 47 [2] 14 65 [2] 00 7e [2] 0f 64 [2] 11 79 [2] 13 78 [2] 08 7e [2] 14 79 [2] 08 56 }

  condition:
    any of them
}