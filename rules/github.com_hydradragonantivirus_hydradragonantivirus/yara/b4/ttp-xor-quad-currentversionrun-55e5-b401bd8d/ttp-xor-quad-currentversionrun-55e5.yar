rule TTP_XOR_QUAD_CurrentVersionRun_55e5 {
  strings:
    $key_55e5 = { 06 8a [2] 22 84 [2] 09 a8 [2] 27 8a [2] 33 91 [2] 3c 8b [2] 22 96 [2] 20 97 [2] 3b 91 [2] 27 96 [2] 3b b9 }

  condition:
    any of them
}