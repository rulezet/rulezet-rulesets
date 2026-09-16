rule TTP_XOR_QUAD_CurrentVersionRun_2818 {
  strings:
    $key_2818 = { 7b 77 [2] 5f 79 [2] 74 55 [2] 5a 77 [2] 4e 6c [2] 41 76 [2] 5f 6b [2] 5d 6a [2] 46 6c [2] 5a 6b [2] 46 44 }

  condition:
    any of them
}