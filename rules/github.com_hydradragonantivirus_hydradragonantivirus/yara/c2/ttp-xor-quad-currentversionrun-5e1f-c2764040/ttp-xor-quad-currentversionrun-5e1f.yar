rule TTP_XOR_QUAD_CurrentVersionRun_5e1f {
  strings:
    $key_5e1f = { 0d 70 [2] 29 7e [2] 02 52 [2] 2c 70 [2] 38 6b [2] 37 71 [2] 29 6c [2] 2b 6d [2] 30 6b [2] 2c 6c [2] 30 43 }

  condition:
    any of them
}