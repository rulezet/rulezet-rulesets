rule TTP_XOR_QUAD_CurrentVersionRun_09f8 {
  strings:
    $key_09f8 = { 5a 97 [2] 7e 99 [2] 55 b5 [2] 7b 97 [2] 6f 8c [2] 60 96 [2] 7e 8b [2] 7c 8a [2] 67 8c [2] 7b 8b [2] 67 a4 }

  condition:
    any of them
}