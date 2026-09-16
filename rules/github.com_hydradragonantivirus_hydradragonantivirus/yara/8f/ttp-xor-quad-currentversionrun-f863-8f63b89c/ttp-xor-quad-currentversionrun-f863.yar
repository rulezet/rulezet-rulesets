rule TTP_XOR_QUAD_CurrentVersionRun_f863 {
  strings:
    $key_f863 = { ab 0c [2] 8f 02 [2] a4 2e [2] 8a 0c [2] 9e 17 [2] 91 0d [2] 8f 10 [2] 8d 11 [2] 96 17 [2] 8a 10 [2] 96 3f }

  condition:
    any of them
}