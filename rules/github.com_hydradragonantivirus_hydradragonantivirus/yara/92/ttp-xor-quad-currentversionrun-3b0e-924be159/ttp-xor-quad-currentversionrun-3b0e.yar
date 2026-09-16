rule TTP_XOR_QUAD_CurrentVersionRun_3b0e {
  strings:
    $key_3b0e = { 68 61 [2] 4c 6f [2] 67 43 [2] 49 61 [2] 5d 7a [2] 52 60 [2] 4c 7d [2] 4e 7c [2] 55 7a [2] 49 7d [2] 55 52 }

  condition:
    any of them
}