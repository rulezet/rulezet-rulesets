rule TTP_XOR_QUAD_CurrentVersionRun_3de8 {
  strings:
    $key_3de8 = { 6e 87 [2] 4a 89 [2] 61 a5 [2] 4f 87 [2] 5b 9c [2] 54 86 [2] 4a 9b [2] 48 9a [2] 53 9c [2] 4f 9b [2] 53 b4 }

  condition:
    any of them
}