rule TTP_XOR_QUAD_CurrentVersionRun_7b7f {
  strings:
    $key_7b7f = { 28 10 [2] 0c 1e [2] 27 32 [2] 09 10 [2] 1d 0b [2] 12 11 [2] 0c 0c [2] 0e 0d [2] 15 0b [2] 09 0c [2] 15 23 }

  condition:
    any of them
}