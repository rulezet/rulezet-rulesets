rule TTP_XOR_QUAD_CurrentVersionRun_34e9 {
  strings:
    $key_34e9 = { 67 86 [2] 43 88 [2] 68 a4 [2] 46 86 [2] 52 9d [2] 5d 87 [2] 43 9a [2] 41 9b [2] 5a 9d [2] 46 9a [2] 5a b5 }

  condition:
    any of them
}