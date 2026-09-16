rule TTP_XOR_QUAD_CurrentVersionRun_650a {
  strings:
    $key_650a = { 36 65 [2] 12 6b [2] 39 47 [2] 17 65 [2] 03 7e [2] 0c 64 [2] 12 79 [2] 10 78 [2] 0b 7e [2] 17 79 [2] 0b 56 }

  condition:
    any of them
}