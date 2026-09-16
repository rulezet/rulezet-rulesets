rule TTP_XOR_QUAD_CurrentVersionRun_e8e5 {
  strings:
    $key_e8e5 = { bb 8a [2] 9f 84 [2] b4 a8 [2] 9a 8a [2] 8e 91 [2] 81 8b [2] 9f 96 [2] 9d 97 [2] 86 91 [2] 9a 96 [2] 86 b9 }

  condition:
    any of them
}