rule TTP_XOR_QUAD_CurrentVersionRun_227f {
  strings:
    $key_227f = { 71 10 [2] 55 1e [2] 7e 32 [2] 50 10 [2] 44 0b [2] 4b 11 [2] 55 0c [2] 57 0d [2] 4c 0b [2] 50 0c [2] 4c 23 }

  condition:
    any of them
}