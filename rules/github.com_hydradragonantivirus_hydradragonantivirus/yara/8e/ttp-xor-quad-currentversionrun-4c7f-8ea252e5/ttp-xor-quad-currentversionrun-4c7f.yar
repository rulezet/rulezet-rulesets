rule TTP_XOR_QUAD_CurrentVersionRun_4c7f {
  strings:
    $key_4c7f = { 1f 10 [2] 3b 1e [2] 10 32 [2] 3e 10 [2] 2a 0b [2] 25 11 [2] 3b 0c [2] 39 0d [2] 22 0b [2] 3e 0c [2] 22 23 }

  condition:
    any of them
}