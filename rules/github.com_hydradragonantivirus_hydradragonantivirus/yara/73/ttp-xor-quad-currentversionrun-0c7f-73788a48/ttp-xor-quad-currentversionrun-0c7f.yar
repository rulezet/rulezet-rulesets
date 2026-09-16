rule TTP_XOR_QUAD_CurrentVersionRun_0c7f {
  strings:
    $key_0c7f = { 5f 10 [2] 7b 1e [2] 50 32 [2] 7e 10 [2] 6a 0b [2] 65 11 [2] 7b 0c [2] 79 0d [2] 62 0b [2] 7e 0c [2] 62 23 }

  condition:
    any of them
}