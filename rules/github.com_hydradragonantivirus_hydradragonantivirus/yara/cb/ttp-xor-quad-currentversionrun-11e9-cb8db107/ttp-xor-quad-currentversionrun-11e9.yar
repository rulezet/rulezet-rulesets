rule TTP_XOR_QUAD_CurrentVersionRun_11e9 {
  strings:
    $key_11e9 = { 42 86 [2] 66 88 [2] 4d a4 [2] 63 86 [2] 77 9d [2] 78 87 [2] 66 9a [2] 64 9b [2] 7f 9d [2] 63 9a [2] 7f b5 }

  condition:
    any of them
}