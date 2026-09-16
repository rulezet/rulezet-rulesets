rule TTP_XOR_QUAD_CurrentVersionRun_6be8 {
  strings:
    $key_6be8 = { 38 87 [2] 1c 89 [2] 37 a5 [2] 19 87 [2] 0d 9c [2] 02 86 [2] 1c 9b [2] 1e 9a [2] 05 9c [2] 19 9b [2] 05 b4 }

  condition:
    any of them
}