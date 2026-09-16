rule TTP_XOR_QUAD_CurrentVersionRun_087f {
  strings:
    $key_087f = { 5b 10 [2] 7f 1e [2] 54 32 [2] 7a 10 [2] 6e 0b [2] 61 11 [2] 7f 0c [2] 7d 0d [2] 66 0b [2] 7a 0c [2] 66 23 }

  condition:
    any of them
}