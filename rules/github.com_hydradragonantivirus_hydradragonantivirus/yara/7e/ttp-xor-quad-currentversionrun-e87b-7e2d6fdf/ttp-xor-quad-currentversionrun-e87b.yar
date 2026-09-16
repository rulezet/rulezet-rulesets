rule TTP_XOR_QUAD_CurrentVersionRun_e87b {
  strings:
    $key_e87b = { bb 14 [2] 9f 1a [2] b4 36 [2] 9a 14 [2] 8e 0f [2] 81 15 [2] 9f 08 [2] 9d 09 [2] 86 0f [2] 9a 08 [2] 86 27 }

  condition:
    any of them
}