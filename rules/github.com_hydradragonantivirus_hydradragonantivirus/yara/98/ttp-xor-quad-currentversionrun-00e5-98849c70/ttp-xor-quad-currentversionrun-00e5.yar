rule TTP_XOR_QUAD_CurrentVersionRun_00e5 {
  strings:
    $key_00e5 = { 53 8a [2] 77 84 [2] 5c a8 [2] 72 8a [2] 66 91 [2] 69 8b [2] 77 96 [2] 75 97 [2] 6e 91 [2] 72 96 [2] 6e b9 }

  condition:
    any of them
}