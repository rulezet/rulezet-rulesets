rule TTP_XOR_QUAD_CurrentVersionRun_1bfd {
  strings:
    $key_1bfd = { 48 92 [2] 6c 9c [2] 47 b0 [2] 69 92 [2] 7d 89 [2] 72 93 [2] 6c 8e [2] 6e 8f [2] 75 89 [2] 69 8e [2] 75 a1 }

  condition:
    any of them
}