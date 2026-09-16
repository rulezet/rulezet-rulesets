rule TTP_XOR_QUAD_CurrentVersionRun_5e0f {
  strings:
    $key_5e0f = { 0d 60 [2] 29 6e [2] 02 42 [2] 2c 60 [2] 38 7b [2] 37 61 [2] 29 7c [2] 2b 7d [2] 30 7b [2] 2c 7c [2] 30 53 }

  condition:
    any of them
}