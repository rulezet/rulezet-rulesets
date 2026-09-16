rule TTP_XOR_QUAD_CurrentVersionRun_707f {
  strings:
    $key_707f = { 23 10 [2] 07 1e [2] 2c 32 [2] 02 10 [2] 16 0b [2] 19 11 [2] 07 0c [2] 05 0d [2] 1e 0b [2] 02 0c [2] 1e 23 }

  condition:
    any of them
}