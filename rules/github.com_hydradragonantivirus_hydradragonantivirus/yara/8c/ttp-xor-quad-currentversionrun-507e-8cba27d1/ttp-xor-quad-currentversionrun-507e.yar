rule TTP_XOR_QUAD_CurrentVersionRun_507e {
  strings:
    $key_507e = { 03 11 [2] 27 1f [2] 0c 33 [2] 22 11 [2] 36 0a [2] 39 10 [2] 27 0d [2] 25 0c [2] 3e 0a [2] 22 0d [2] 3e 22 }

  condition:
    any of them
}