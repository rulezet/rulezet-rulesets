rule TTP_XOR_QUAD_CurrentVersionRun_0115 {
  strings:
    $key_0115 = { 52 7a [2] 76 74 [2] 5d 58 [2] 73 7a [2] 67 61 [2] 68 7b [2] 76 66 [2] 74 67 [2] 6f 61 [2] 73 66 [2] 6f 49 }

  condition:
    any of them
}