rule TTP_XOR_QUAD_CurrentVersionRun_0e08 {
  strings:
    $key_0e08 = { 5d 67 [2] 79 69 [2] 52 45 [2] 7c 67 [2] 68 7c [2] 67 66 [2] 79 7b [2] 7b 7a [2] 60 7c [2] 7c 7b [2] 60 54 }

  condition:
    any of them
}