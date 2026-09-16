rule TTP_XOR_QUAD_CurrentVersionRun_450e {
  strings:
    $key_450e = { 16 61 [2] 32 6f [2] 19 43 [2] 37 61 [2] 23 7a [2] 2c 60 [2] 32 7d [2] 30 7c [2] 2b 7a [2] 37 7d [2] 2b 52 }

  condition:
    any of them
}