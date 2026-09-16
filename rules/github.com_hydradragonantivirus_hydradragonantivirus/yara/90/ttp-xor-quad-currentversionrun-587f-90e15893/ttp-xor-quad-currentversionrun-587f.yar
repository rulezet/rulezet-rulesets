rule TTP_XOR_QUAD_CurrentVersionRun_587f {
  strings:
    $key_587f = { 0b 10 [2] 2f 1e [2] 04 32 [2] 2a 10 [2] 3e 0b [2] 31 11 [2] 2f 0c [2] 2d 0d [2] 36 0b [2] 2a 0c [2] 36 23 }

  condition:
    any of them
}