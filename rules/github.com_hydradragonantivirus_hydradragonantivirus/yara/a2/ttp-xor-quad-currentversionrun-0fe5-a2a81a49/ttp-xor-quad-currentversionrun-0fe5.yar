rule TTP_XOR_QUAD_CurrentVersionRun_0fe5 {
  strings:
    $key_0fe5 = { 5c 8a [2] 78 84 [2] 53 a8 [2] 7d 8a [2] 69 91 [2] 66 8b [2] 78 96 [2] 7a 97 [2] 61 91 [2] 7d 96 [2] 61 b9 }

  condition:
    any of them
}