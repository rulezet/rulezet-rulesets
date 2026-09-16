rule TTP_XOR_QUAD_CurrentVersionRun_09f9 {
  strings:
    $key_09f9 = { 5a 96 [2] 7e 98 [2] 55 b4 [2] 7b 96 [2] 6f 8d [2] 60 97 [2] 7e 8a [2] 7c 8b [2] 67 8d [2] 7b 8a [2] 67 a5 }

  condition:
    any of them
}