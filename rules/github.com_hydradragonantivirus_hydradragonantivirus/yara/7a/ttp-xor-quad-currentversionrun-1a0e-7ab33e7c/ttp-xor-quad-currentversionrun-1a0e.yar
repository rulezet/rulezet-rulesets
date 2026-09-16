rule TTP_XOR_QUAD_CurrentVersionRun_1a0e {
  strings:
    $key_1a0e = { 49 61 [2] 6d 6f [2] 46 43 [2] 68 61 [2] 7c 7a [2] 73 60 [2] 6d 7d [2] 6f 7c [2] 74 7a [2] 68 7d [2] 74 52 }

  condition:
    any of them
}