rule TTP_XOR_QUAD_CurrentVersionRun_f8e5 {
  strings:
    $key_f8e5 = { ab 8a [2] 8f 84 [2] a4 a8 [2] 8a 8a [2] 9e 91 [2] 91 8b [2] 8f 96 [2] 8d 97 [2] 96 91 [2] 8a 96 [2] 96 b9 }

  condition:
    any of them
}