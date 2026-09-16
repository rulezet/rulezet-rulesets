rule TTP_XOR_QUAD_CurrentVersionRun_38e9 {
  strings:
    $key_38e9 = { 6b 86 [2] 4f 88 [2] 64 a4 [2] 4a 86 [2] 5e 9d [2] 51 87 [2] 4f 9a [2] 4d 9b [2] 56 9d [2] 4a 9a [2] 56 b5 }

  condition:
    any of them
}