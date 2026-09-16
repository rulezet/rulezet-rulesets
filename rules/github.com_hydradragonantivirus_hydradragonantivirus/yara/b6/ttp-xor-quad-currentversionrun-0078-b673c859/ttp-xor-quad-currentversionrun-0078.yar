rule TTP_XOR_QUAD_CurrentVersionRun_0078 {
  strings:
    $key_0078 = { 53 17 [2] 77 19 [2] 5c 35 [2] 72 17 [2] 66 0c [2] 69 16 [2] 77 0b [2] 75 0a [2] 6e 0c [2] 72 0b [2] 6e 24 }

  condition:
    any of them
}