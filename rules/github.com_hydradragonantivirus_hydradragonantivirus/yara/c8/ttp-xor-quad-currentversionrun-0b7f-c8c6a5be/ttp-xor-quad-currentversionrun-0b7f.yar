rule TTP_XOR_QUAD_CurrentVersionRun_0b7f {
  strings:
    $key_0b7f = { 58 10 [2] 7c 1e [2] 57 32 [2] 79 10 [2] 6d 0b [2] 62 11 [2] 7c 0c [2] 7e 0d [2] 65 0b [2] 79 0c [2] 65 23 }

  condition:
    any of them
}