rule TTP_XOR_QUAD_CurrentVersionRun_3715 {
  strings:
    $key_3715 = { 64 7a [2] 40 74 [2] 6b 58 [2] 45 7a [2] 51 61 [2] 5e 7b [2] 40 66 [2] 42 67 [2] 59 61 [2] 45 66 [2] 59 49 }

  condition:
    any of them
}