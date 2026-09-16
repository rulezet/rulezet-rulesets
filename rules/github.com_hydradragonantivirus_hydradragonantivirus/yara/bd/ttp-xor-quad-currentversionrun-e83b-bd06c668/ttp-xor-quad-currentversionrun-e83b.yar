rule TTP_XOR_QUAD_CurrentVersionRun_e83b {
  strings:
    $key_e83b = { bb 54 [2] 9f 5a [2] b4 76 [2] 9a 54 [2] 8e 4f [2] 81 55 [2] 9f 48 [2] 9d 49 [2] 86 4f [2] 9a 48 [2] 86 67 }

  condition:
    any of them
}