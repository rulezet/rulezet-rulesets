rule TTP_XOR_QUAD_CurrentVersionRun_620a {
  strings:
    $key_620a = { 31 65 [2] 15 6b [2] 3e 47 [2] 10 65 [2] 04 7e [2] 0b 64 [2] 15 79 [2] 17 78 [2] 0c 7e [2] 10 79 [2] 0c 56 }

  condition:
    any of them
}