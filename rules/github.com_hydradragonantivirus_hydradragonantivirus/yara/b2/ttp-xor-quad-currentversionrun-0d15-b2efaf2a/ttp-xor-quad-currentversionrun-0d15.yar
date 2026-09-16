rule TTP_XOR_QUAD_CurrentVersionRun_0d15 {
  strings:
    $key_0d15 = { 5e 7a [2] 7a 74 [2] 51 58 [2] 7f 7a [2] 6b 61 [2] 64 7b [2] 7a 66 [2] 78 67 [2] 63 61 [2] 7f 66 [2] 63 49 }

  condition:
    any of them
}