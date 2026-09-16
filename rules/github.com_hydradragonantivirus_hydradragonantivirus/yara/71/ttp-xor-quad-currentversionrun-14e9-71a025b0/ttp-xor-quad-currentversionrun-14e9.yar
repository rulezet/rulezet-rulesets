rule TTP_XOR_QUAD_CurrentVersionRun_14e9 {
  strings:
    $key_14e9 = { 47 86 [2] 63 88 [2] 48 a4 [2] 66 86 [2] 72 9d [2] 7d 87 [2] 63 9a [2] 61 9b [2] 7a 9d [2] 66 9a [2] 7a b5 }

  condition:
    any of them
}