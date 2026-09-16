rule TTP_XOR_QUAD_CurrentVersionRun_30c7 {
  strings:
    $key_30c7 = { 63 a8 [2] 47 a6 [2] 6c 8a [2] 42 a8 [2] 56 b3 [2] 59 a9 [2] 47 b4 [2] 45 b5 [2] 5e b3 [2] 42 b4 [2] 5e 9b }

  condition:
    any of them
}