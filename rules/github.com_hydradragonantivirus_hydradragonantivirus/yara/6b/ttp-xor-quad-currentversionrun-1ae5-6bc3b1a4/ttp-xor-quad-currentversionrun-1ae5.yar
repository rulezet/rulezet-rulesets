rule TTP_XOR_QUAD_CurrentVersionRun_1ae5 {
  strings:
    $key_1ae5 = { 49 8a [2] 6d 84 [2] 46 a8 [2] 68 8a [2] 7c 91 [2] 73 8b [2] 6d 96 [2] 6f 97 [2] 74 91 [2] 68 96 [2] 74 b9 }

  condition:
    any of them
}