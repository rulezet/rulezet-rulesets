rule TTP_XOR_QUAD_CurrentVersionRun_34e4 {
  strings:
    $key_34e4 = { 67 8b [2] 43 85 [2] 68 a9 [2] 46 8b [2] 52 90 [2] 5d 8a [2] 43 97 [2] 41 96 [2] 5a 90 [2] 46 97 [2] 5a b8 }

  condition:
    any of them
}