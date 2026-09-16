rule TTP_XOR_QUAD_CurrentVersionRun_10e5 {
  strings:
    $key_10e5 = { 43 8a [2] 67 84 [2] 4c a8 [2] 62 8a [2] 76 91 [2] 79 8b [2] 67 96 [2] 65 97 [2] 7e 91 [2] 62 96 [2] 7e b9 }

  condition:
    any of them
}