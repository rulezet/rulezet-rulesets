rule TTP_XOR_QUAD_CurrentVersionRun_f8e8 {
  strings:
    $key_f8e8 = { ab 87 [2] 8f 89 [2] a4 a5 [2] 8a 87 [2] 9e 9c [2] 91 86 [2] 8f 9b [2] 8d 9a [2] 96 9c [2] 8a 9b [2] 96 b4 }

  condition:
    any of them
}