rule TTP_XOR_QUAD_CurrentVersionRun_3e0e {
  strings:
    $key_3e0e = { 6d 61 [2] 49 6f [2] 62 43 [2] 4c 61 [2] 58 7a [2] 57 60 [2] 49 7d [2] 4b 7c [2] 50 7a [2] 4c 7d [2] 50 52 }

  condition:
    any of them
}