rule TTP_XOR_QUAD_CurrentVersionRun_5008 {
  strings:
    $key_5008 = { 03 67 [2] 27 69 [2] 0c 45 [2] 22 67 [2] 36 7c [2] 39 66 [2] 27 7b [2] 25 7a [2] 3e 7c [2] 22 7b [2] 3e 54 }

  condition:
    any of them
}