rule TTP_XOR_QUAD_CurrentVersionRun_f839 {
  strings:
    $key_f839 = { ab 56 [2] 8f 58 [2] a4 74 [2] 8a 56 [2] 9e 4d [2] 91 57 [2] 8f 4a [2] 8d 4b [2] 96 4d [2] 8a 4a [2] 96 65 }

  condition:
    any of them
}