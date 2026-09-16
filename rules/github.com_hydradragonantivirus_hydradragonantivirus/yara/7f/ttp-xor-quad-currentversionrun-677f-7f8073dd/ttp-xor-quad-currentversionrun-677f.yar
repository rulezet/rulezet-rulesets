rule TTP_XOR_QUAD_CurrentVersionRun_677f {
  strings:
    $key_677f = { 34 10 [2] 10 1e [2] 3b 32 [2] 15 10 [2] 01 0b [2] 0e 11 [2] 10 0c [2] 12 0d [2] 09 0b [2] 15 0c [2] 09 23 }

  condition:
    any of them
}