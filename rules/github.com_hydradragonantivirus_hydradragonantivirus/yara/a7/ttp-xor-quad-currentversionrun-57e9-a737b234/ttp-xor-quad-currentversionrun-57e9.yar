rule TTP_XOR_QUAD_CurrentVersionRun_57e9 {
  strings:
    $key_57e9 = { 04 86 [2] 20 88 [2] 0b a4 [2] 25 86 [2] 31 9d [2] 3e 87 [2] 20 9a [2] 22 9b [2] 39 9d [2] 25 9a [2] 39 b5 }

  condition:
    any of them
}