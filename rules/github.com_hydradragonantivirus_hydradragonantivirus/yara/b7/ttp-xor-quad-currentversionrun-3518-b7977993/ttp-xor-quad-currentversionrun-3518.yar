rule TTP_XOR_QUAD_CurrentVersionRun_3518 {
  strings:
    $key_3518 = { 66 77 [2] 42 79 [2] 69 55 [2] 47 77 [2] 53 6c [2] 5c 76 [2] 42 6b [2] 40 6a [2] 5b 6c [2] 47 6b [2] 5b 44 }

  condition:
    any of them
}