rule TTP_XOR_QUAD_CurrentVersionRun_1c7f {
  strings:
    $key_1c7f = { 4f 10 [2] 6b 1e [2] 40 32 [2] 6e 10 [2] 7a 0b [2] 75 11 [2] 6b 0c [2] 69 0d [2] 72 0b [2] 6e 0c [2] 72 23 }

  condition:
    any of them
}