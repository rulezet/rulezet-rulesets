rule TTP_XOR_QUAD_CurrentVersionRun_2715 {
  strings:
    $key_2715 = { 74 7a [2] 50 74 [2] 7b 58 [2] 55 7a [2] 41 61 [2] 4e 7b [2] 50 66 [2] 52 67 [2] 49 61 [2] 55 66 [2] 49 49 }

  condition:
    any of them
}