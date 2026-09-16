rule TTP_XOR_QUAD_CurrentVersionRun_4fe5 {
  strings:
    $key_4fe5 = { 1c 8a [2] 38 84 [2] 13 a8 [2] 3d 8a [2] 29 91 [2] 26 8b [2] 38 96 [2] 3a 97 [2] 21 91 [2] 3d 96 [2] 21 b9 }

  condition:
    any of them
}