rule TTP_XOR_QUAD_CurrentVersionRun_187f {
  strings:
    $key_187f = { 4b 10 [2] 6f 1e [2] 44 32 [2] 6a 10 [2] 7e 0b [2] 71 11 [2] 6f 0c [2] 6d 0d [2] 76 0b [2] 6a 0c [2] 76 23 }

  condition:
    any of them
}