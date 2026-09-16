rule TTP_XOR_QUAD_CurrentVersionRun_e8f9 {
  strings:
    $key_e8f9 = { bb 96 [2] 9f 98 [2] b4 b4 [2] 9a 96 [2] 8e 8d [2] 81 97 [2] 9f 8a [2] 9d 8b [2] 86 8d [2] 9a 8a [2] 86 a5 }

  condition:
    any of them
}