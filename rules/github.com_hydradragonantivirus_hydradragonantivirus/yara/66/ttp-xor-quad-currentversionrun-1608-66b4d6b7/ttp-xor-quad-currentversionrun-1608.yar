rule TTP_XOR_QUAD_CurrentVersionRun_1608 {
  strings:
    $key_1608 = { 45 67 [2] 61 69 [2] 4a 45 [2] 64 67 [2] 70 7c [2] 7f 66 [2] 61 7b [2] 63 7a [2] 78 7c [2] 64 7b [2] 78 54 }

  condition:
    any of them
}