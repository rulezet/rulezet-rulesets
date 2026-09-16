rule TTP_XOR_QUAD_CurrentVersionRun_34e5 {
  strings:
    $key_34e5 = { 67 8a [2] 43 84 [2] 68 a8 [2] 46 8a [2] 52 91 [2] 5d 8b [2] 43 96 [2] 41 97 [2] 5a 91 [2] 46 96 [2] 5a b9 }

  condition:
    any of them
}