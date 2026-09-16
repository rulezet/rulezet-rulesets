rule TTP_XOR_QUAD_CurrentVersionRun_6ae8 {
  strings:
    $key_6ae8 = { 39 87 [2] 1d 89 [2] 36 a5 [2] 18 87 [2] 0c 9c [2] 03 86 [2] 1d 9b [2] 1f 9a [2] 04 9c [2] 18 9b [2] 04 b4 }

  condition:
    any of them
}