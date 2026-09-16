rule TTP_XOR_QUAD_CurrentVersionRun_647f {
  strings:
    $key_647f = { 37 10 [2] 13 1e [2] 38 32 [2] 16 10 [2] 02 0b [2] 0d 11 [2] 13 0c [2] 11 0d [2] 0a 0b [2] 16 0c [2] 0a 23 }

  condition:
    any of them
}