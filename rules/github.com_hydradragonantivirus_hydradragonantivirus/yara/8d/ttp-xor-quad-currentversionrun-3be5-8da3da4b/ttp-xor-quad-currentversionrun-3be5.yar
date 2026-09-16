rule TTP_XOR_QUAD_CurrentVersionRun_3be5 {
  strings:
    $key_3be5 = { 68 8a [2] 4c 84 [2] 67 a8 [2] 49 8a [2] 5d 91 [2] 52 8b [2] 4c 96 [2] 4e 97 [2] 55 91 [2] 49 96 [2] 55 b9 }

  condition:
    any of them
}