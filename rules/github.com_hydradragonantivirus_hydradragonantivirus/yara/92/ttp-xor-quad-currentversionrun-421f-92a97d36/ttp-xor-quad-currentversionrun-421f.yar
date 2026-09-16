rule TTP_XOR_QUAD_CurrentVersionRun_421f {
  strings:
    $key_421f = { 11 70 [2] 35 7e [2] 1e 52 [2] 30 70 [2] 24 6b [2] 2b 71 [2] 35 6c [2] 37 6d [2] 2c 6b [2] 30 6c [2] 2c 43 }

  condition:
    any of them
}