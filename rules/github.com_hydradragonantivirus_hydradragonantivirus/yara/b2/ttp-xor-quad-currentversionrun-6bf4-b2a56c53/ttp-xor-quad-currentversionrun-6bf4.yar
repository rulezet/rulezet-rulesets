rule TTP_XOR_QUAD_CurrentVersionRun_6bf4 {
  strings:
    $key_6bf4 = { 38 9b [2] 1c 95 [2] 37 b9 [2] 19 9b [2] 0d 80 [2] 02 9a [2] 1c 87 [2] 1e 86 [2] 05 80 [2] 19 87 [2] 05 a8 }

  condition:
    any of them
}