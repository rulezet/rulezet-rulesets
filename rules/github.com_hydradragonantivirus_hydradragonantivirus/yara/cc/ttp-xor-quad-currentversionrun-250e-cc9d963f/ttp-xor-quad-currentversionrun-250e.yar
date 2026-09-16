rule TTP_XOR_QUAD_CurrentVersionRun_250e {
  strings:
    $key_250e = { 76 61 [2] 52 6f [2] 79 43 [2] 57 61 [2] 43 7a [2] 4c 60 [2] 52 7d [2] 50 7c [2] 4b 7a [2] 57 7d [2] 4b 52 }

  condition:
    any of them
}