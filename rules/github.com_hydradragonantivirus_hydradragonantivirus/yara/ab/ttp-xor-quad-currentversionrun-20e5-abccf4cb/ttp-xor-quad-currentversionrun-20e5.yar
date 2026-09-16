rule TTP_XOR_QUAD_CurrentVersionRun_20e5 {
  strings:
    $key_20e5 = { 73 8a [2] 57 84 [2] 7c a8 [2] 52 8a [2] 46 91 [2] 49 8b [2] 57 96 [2] 55 97 [2] 4e 91 [2] 52 96 [2] 4e b9 }

  condition:
    any of them
}