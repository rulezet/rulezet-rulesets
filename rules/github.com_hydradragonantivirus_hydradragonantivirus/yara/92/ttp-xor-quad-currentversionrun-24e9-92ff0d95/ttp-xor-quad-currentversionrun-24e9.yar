rule TTP_XOR_QUAD_CurrentVersionRun_24e9 {
  strings:
    $key_24e9 = { 77 86 [2] 53 88 [2] 78 a4 [2] 56 86 [2] 42 9d [2] 4d 87 [2] 53 9a [2] 51 9b [2] 4a 9d [2] 56 9a [2] 4a b5 }

  condition:
    any of them
}