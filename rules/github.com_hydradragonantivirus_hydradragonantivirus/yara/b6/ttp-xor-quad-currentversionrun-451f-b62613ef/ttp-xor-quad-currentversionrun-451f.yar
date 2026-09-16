rule TTP_XOR_QUAD_CurrentVersionRun_451f {
  strings:
    $key_451f = { 16 70 [2] 32 7e [2] 19 52 [2] 37 70 [2] 23 6b [2] 2c 71 [2] 32 6c [2] 30 6d [2] 2b 6b [2] 37 6c [2] 2b 43 }

  condition:
    any of them
}