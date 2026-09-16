rule TTP_XOR_QUAD_CurrentVersionRun_6dfd {
  strings:
    $key_6dfd = { 3e 92 [2] 1a 9c [2] 31 b0 [2] 1f 92 [2] 0b 89 [2] 04 93 [2] 1a 8e [2] 18 8f [2] 03 89 [2] 1f 8e [2] 03 a1 }

  condition:
    any of them
}