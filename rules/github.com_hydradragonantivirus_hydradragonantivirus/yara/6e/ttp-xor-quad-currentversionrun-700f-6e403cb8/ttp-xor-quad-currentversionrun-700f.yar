rule TTP_XOR_QUAD_CurrentVersionRun_700f {
  strings:
    $key_700f = { 23 60 [2] 07 6e [2] 2c 42 [2] 02 60 [2] 16 7b [2] 19 61 [2] 07 7c [2] 05 7d [2] 1e 7b [2] 02 7c [2] 1e 53 }

  condition:
    any of them
}