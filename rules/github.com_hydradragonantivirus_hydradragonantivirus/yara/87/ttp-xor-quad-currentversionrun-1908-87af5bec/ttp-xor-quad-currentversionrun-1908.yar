rule TTP_XOR_QUAD_CurrentVersionRun_1908 {
  strings:
    $key_1908 = { 4a 67 [2] 6e 69 [2] 45 45 [2] 6b 67 [2] 7f 7c [2] 70 66 [2] 6e 7b [2] 6c 7a [2] 77 7c [2] 6b 7b [2] 77 54 }

  condition:
    any of them
}