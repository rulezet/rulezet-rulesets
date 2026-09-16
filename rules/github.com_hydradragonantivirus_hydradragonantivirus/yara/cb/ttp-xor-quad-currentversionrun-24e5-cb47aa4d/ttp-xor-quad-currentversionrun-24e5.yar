rule TTP_XOR_QUAD_CurrentVersionRun_24e5 {
  strings:
    $key_24e5 = { 77 8a [2] 53 84 [2] 78 a8 [2] 56 8a [2] 42 91 [2] 4d 8b [2] 53 96 [2] 51 97 [2] 4a 91 [2] 56 96 [2] 4a b9 }

  condition:
    any of them
}