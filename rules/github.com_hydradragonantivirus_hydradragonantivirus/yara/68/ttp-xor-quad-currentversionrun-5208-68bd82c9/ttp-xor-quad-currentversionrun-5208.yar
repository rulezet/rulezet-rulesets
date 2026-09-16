rule TTP_XOR_QUAD_CurrentVersionRun_5208 {
  strings:
    $key_5208 = { 01 67 [2] 25 69 [2] 0e 45 [2] 20 67 [2] 34 7c [2] 3b 66 [2] 25 7b [2] 27 7a [2] 3c 7c [2] 20 7b [2] 3c 54 }

  condition:
    any of them
}