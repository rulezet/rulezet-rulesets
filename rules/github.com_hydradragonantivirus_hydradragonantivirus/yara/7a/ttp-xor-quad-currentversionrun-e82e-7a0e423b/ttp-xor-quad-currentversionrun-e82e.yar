rule TTP_XOR_QUAD_CurrentVersionRun_e82e {
  strings:
    $key_e82e = { bb 41 [2] 9f 4f [2] b4 63 [2] 9a 41 [2] 8e 5a [2] 81 40 [2] 9f 5d [2] 9d 5c [2] 86 5a [2] 9a 5d [2] 86 72 }

  condition:
    any of them
}