rule TTP_XOR_QUAD_CurrentVersionRun_2d7e {
  strings:
    $key_2d7e = { 7e 11 [2] 5a 1f [2] 71 33 [2] 5f 11 [2] 4b 0a [2] 44 10 [2] 5a 0d [2] 58 0c [2] 43 0a [2] 5f 0d [2] 43 22 }

  condition:
    any of them
}