rule TTP_XOR_QUAD_CurrentVersionRun_557f {
  strings:
    $key_557f = { 06 10 [2] 22 1e [2] 09 32 [2] 27 10 [2] 33 0b [2] 3c 11 [2] 22 0c [2] 20 0d [2] 3b 0b [2] 27 0c [2] 3b 23 }

  condition:
    any of them
}