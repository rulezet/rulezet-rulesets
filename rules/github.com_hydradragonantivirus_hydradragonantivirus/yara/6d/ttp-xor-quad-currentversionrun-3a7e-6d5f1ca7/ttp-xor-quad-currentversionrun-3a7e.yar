rule TTP_XOR_QUAD_CurrentVersionRun_3a7e {
  strings:
    $key_3a7e = { 69 11 [2] 4d 1f [2] 66 33 [2] 48 11 [2] 5c 0a [2] 53 10 [2] 4d 0d [2] 4f 0c [2] 54 0a [2] 48 0d [2] 54 22 }

  condition:
    any of them
}