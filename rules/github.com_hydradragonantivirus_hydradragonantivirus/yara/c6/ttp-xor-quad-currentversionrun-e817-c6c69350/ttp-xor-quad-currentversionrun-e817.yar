rule TTP_XOR_QUAD_CurrentVersionRun_e817 {
  strings:
    $key_e817 = { bb 78 [2] 9f 76 [2] b4 5a [2] 9a 78 [2] 8e 63 [2] 81 79 [2] 9f 64 [2] 9d 65 [2] 86 63 [2] 9a 64 [2] 86 4b }

  condition:
    any of them
}