rule TTP_XOR_QUAD_CurrentVersionRun_30e9 {
  strings:
    $key_30e9 = { 63 86 [2] 47 88 [2] 6c a4 [2] 42 86 [2] 56 9d [2] 59 87 [2] 47 9a [2] 45 9b [2] 5e 9d [2] 42 9a [2] 5e b5 }

  condition:
    any of them
}