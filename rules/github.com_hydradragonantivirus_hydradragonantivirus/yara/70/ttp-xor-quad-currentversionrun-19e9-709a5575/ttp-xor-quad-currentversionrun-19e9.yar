rule TTP_XOR_QUAD_CurrentVersionRun_19e9 {
  strings:
    $key_19e9 = { 4a 86 [2] 6e 88 [2] 45 a4 [2] 6b 86 [2] 7f 9d [2] 70 87 [2] 6e 9a [2] 6c 9b [2] 77 9d [2] 6b 9a [2] 77 b5 }

  condition:
    any of them
}