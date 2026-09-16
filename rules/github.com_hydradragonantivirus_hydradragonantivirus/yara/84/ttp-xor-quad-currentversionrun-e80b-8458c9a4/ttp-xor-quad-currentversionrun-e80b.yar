rule TTP_XOR_QUAD_CurrentVersionRun_e80b {
  strings:
    $key_e80b = { bb 64 [2] 9f 6a [2] b4 46 [2] 9a 64 [2] 8e 7f [2] 81 65 [2] 9f 78 [2] 9d 79 [2] 86 7f [2] 9a 78 [2] 86 57 }

  condition:
    any of them
}