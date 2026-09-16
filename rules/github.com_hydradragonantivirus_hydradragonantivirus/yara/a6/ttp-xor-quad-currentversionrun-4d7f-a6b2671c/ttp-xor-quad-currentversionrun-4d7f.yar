rule TTP_XOR_QUAD_CurrentVersionRun_4d7f {
  strings:
    $key_4d7f = { 1e 10 [2] 3a 1e [2] 11 32 [2] 3f 10 [2] 2b 0b [2] 24 11 [2] 3a 0c [2] 38 0d [2] 23 0b [2] 3f 0c [2] 23 23 }

  condition:
    any of them
}