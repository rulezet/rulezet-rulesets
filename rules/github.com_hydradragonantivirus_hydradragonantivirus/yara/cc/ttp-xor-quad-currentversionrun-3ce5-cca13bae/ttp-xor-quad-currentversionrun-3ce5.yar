rule TTP_XOR_QUAD_CurrentVersionRun_3ce5 {
  strings:
    $key_3ce5 = { 6f 8a [2] 4b 84 [2] 60 a8 [2] 4e 8a [2] 5a 91 [2] 55 8b [2] 4b 96 [2] 49 97 [2] 52 91 [2] 4e 96 [2] 52 b9 }

  condition:
    any of them
}