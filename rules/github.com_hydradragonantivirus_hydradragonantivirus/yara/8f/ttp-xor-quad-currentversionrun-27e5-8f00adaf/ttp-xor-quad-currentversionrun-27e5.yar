rule TTP_XOR_QUAD_CurrentVersionRun_27e5 {
  strings:
    $key_27e5 = { 74 8a [2] 50 84 [2] 7b a8 [2] 55 8a [2] 41 91 [2] 4e 8b [2] 50 96 [2] 52 97 [2] 49 91 [2] 55 96 [2] 49 b9 }

  condition:
    any of them
}