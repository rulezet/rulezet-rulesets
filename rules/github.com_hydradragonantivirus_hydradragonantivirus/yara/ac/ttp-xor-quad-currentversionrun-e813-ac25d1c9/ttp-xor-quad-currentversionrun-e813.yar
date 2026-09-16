rule TTP_XOR_QUAD_CurrentVersionRun_e813 {
  strings:
    $key_e813 = { bb 7c [2] 9f 72 [2] b4 5e [2] 9a 7c [2] 8e 67 [2] 81 7d [2] 9f 60 [2] 9d 61 [2] 86 67 [2] 9a 60 [2] 86 4f }

  condition:
    any of them
}