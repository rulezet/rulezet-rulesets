rule TTP_XOR_QUAD_CurrentVersionRun_0d08 {
  strings:
    $key_0d08 = { 5e 67 [2] 7a 69 [2] 51 45 [2] 7f 67 [2] 6b 7c [2] 64 66 [2] 7a 7b [2] 78 7a [2] 63 7c [2] 7f 7b [2] 63 54 }

  condition:
    any of them
}