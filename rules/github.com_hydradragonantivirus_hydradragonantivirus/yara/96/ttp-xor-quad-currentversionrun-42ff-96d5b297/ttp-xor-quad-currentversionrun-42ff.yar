rule TTP_XOR_QUAD_CurrentVersionRun_42ff {
  strings:
    $key_42ff = { 11 90 [2] 35 9e [2] 1e b2 [2] 30 90 [2] 24 8b [2] 2b 91 [2] 35 8c [2] 37 8d [2] 2c 8b [2] 30 8c [2] 2c a3 }

  condition:
    any of them
}