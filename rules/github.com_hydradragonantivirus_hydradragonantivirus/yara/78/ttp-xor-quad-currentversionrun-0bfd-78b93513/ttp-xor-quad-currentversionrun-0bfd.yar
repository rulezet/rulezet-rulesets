rule TTP_XOR_QUAD_CurrentVersionRun_0bfd {
  strings:
    $key_0bfd = { 58 92 [2] 7c 9c [2] 57 b0 [2] 79 92 [2] 6d 89 [2] 62 93 [2] 7c 8e [2] 7e 8f [2] 65 89 [2] 79 8e [2] 65 a1 }

  condition:
    any of them
}