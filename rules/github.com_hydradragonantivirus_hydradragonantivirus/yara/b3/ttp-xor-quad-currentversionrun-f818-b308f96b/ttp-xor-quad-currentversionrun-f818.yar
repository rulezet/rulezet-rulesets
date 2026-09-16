rule TTP_XOR_QUAD_CurrentVersionRun_f818 {
  strings:
    $key_f818 = { ab 77 [2] 8f 79 [2] a4 55 [2] 8a 77 [2] 9e 6c [2] 91 76 [2] 8f 6b [2] 8d 6a [2] 96 6c [2] 8a 6b [2] 96 44 }

  condition:
    any of them
}