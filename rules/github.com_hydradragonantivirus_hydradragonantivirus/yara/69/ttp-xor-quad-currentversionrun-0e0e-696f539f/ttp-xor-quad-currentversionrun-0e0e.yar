rule TTP_XOR_QUAD_CurrentVersionRun_0e0e {
  strings:
    $key_0e0e = { 5d 61 [2] 79 6f [2] 52 43 [2] 7c 61 [2] 68 7a [2] 67 60 [2] 79 7d [2] 7b 7c [2] 60 7a [2] 7c 7d [2] 60 52 }

  condition:
    any of them
}