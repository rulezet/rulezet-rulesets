rule TTP_XOR_QUAD_CurrentVersionRun_507c {
  strings:
    $key_507c = { 03 13 [2] 27 1d [2] 0c 31 [2] 22 13 [2] 36 08 [2] 39 12 [2] 27 0f [2] 25 0e [2] 3e 08 [2] 22 0f [2] 3e 20 }

  condition:
    any of them
}