rule TTP_XOR_QUAD_CurrentVersionRun_0114 {
  strings:
    $key_0114 = { 52 7b [2] 76 75 [2] 5d 59 [2] 73 7b [2] 67 60 [2] 68 7a [2] 76 67 [2] 74 66 [2] 6f 60 [2] 73 67 [2] 6f 48 }

  condition:
    any of them
}