rule TTP_XOR_QUAD_CurrentVersionRun_0134 {
  strings:
    $key_0134 = { 52 5b [2] 76 55 [2] 5d 79 [2] 73 5b [2] 67 40 [2] 68 5a [2] 76 47 [2] 74 46 [2] 6f 40 [2] 73 47 [2] 6f 68 }

  condition:
    any of them
}