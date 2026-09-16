rule TTP_XOR_QUAD_CurrentVersionRun_e87e {
  strings:
    $key_e87e = { bb 11 [2] 9f 1f [2] b4 33 [2] 9a 11 [2] 8e 0a [2] 81 10 [2] 9f 0d [2] 9d 0c [2] 86 0a [2] 9a 0d [2] 86 22 }

  condition:
    any of them
}