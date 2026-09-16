rule TTP_XOR_QUAD_CurrentVersionRun_1818 {
  strings:
    $key_1818 = { 4b 77 [2] 6f 79 [2] 44 55 [2] 6a 77 [2] 7e 6c [2] 71 76 [2] 6f 6b [2] 6d 6a [2] 76 6c [2] 6a 6b [2] 76 44 }

  condition:
    any of them
}