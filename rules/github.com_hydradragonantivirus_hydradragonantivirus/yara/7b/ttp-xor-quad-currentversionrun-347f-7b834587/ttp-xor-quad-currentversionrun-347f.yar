rule TTP_XOR_QUAD_CurrentVersionRun_347f {
  strings:
    $key_347f = { 67 10 [2] 43 1e [2] 68 32 [2] 46 10 [2] 52 0b [2] 5d 11 [2] 43 0c [2] 41 0d [2] 5a 0b [2] 46 0c [2] 5a 23 }

  condition:
    any of them
}