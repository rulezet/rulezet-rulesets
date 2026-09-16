rule TTP_XOR_QUAD_CurrentVersionRun_64ef {
  strings:
    $key_64ef = { 37 80 [2] 13 8e [2] 38 a2 [2] 16 80 [2] 02 9b [2] 0d 81 [2] 13 9c [2] 11 9d [2] 0a 9b [2] 16 9c [2] 0a b3 }

  condition:
    any of them
}