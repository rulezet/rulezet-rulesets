rule TTP_XOR_QUAD_CurrentVersionRun_3779 {
  strings:
    $key_3779 = { 64 16 [2] 40 18 [2] 6b 34 [2] 45 16 [2] 51 0d [2] 5e 17 [2] 40 0a [2] 42 0b [2] 59 0d [2] 45 0a [2] 59 25 }

  condition:
    any of them
}