rule TTP_XOR_QUAD_CurrentVersionRun_6c7f {
  strings:
    $key_6c7f = { 3f 10 [2] 1b 1e [2] 30 32 [2] 1e 10 [2] 0a 0b [2] 05 11 [2] 1b 0c [2] 19 0d [2] 02 0b [2] 1e 0c [2] 02 23 }

  condition:
    any of them
}