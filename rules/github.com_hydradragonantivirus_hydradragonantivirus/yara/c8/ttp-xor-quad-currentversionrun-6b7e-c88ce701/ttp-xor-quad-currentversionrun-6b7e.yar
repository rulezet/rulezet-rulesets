rule TTP_XOR_QUAD_CurrentVersionRun_6b7e {
  strings:
    $key_6b7e = { 38 11 [2] 1c 1f [2] 37 33 [2] 19 11 [2] 0d 0a [2] 02 10 [2] 1c 0d [2] 1e 0c [2] 05 0a [2] 19 0d [2] 05 22 }

  condition:
    any of them
}