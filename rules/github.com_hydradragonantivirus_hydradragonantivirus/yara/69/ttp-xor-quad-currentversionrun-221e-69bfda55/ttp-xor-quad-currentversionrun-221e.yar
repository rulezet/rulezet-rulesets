rule TTP_XOR_QUAD_CurrentVersionRun_221e {
  strings:
    $key_221e = { 71 71 [2] 55 7f [2] 7e 53 [2] 50 71 [2] 44 6a [2] 4b 70 [2] 55 6d [2] 57 6c [2] 4c 6a [2] 50 6d [2] 4c 42 }

  condition:
    any of them
}