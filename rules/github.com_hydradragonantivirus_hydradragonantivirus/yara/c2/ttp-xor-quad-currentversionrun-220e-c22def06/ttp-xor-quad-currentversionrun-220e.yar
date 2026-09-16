rule TTP_XOR_QUAD_CurrentVersionRun_220e {
  strings:
    $key_220e = { 71 61 [2] 55 6f [2] 7e 43 [2] 50 61 [2] 44 7a [2] 4b 60 [2] 55 7d [2] 57 7c [2] 4c 7a [2] 50 7d [2] 4c 52 }

  condition:
    any of them
}