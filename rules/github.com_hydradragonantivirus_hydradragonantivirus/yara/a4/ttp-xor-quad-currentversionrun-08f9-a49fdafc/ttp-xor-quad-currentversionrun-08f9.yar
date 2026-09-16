rule TTP_XOR_QUAD_CurrentVersionRun_08f9 {
  strings:
    $key_08f9 = { 5b 96 [2] 7f 98 [2] 54 b4 [2] 7a 96 [2] 6e 8d [2] 61 97 [2] 7f 8a [2] 7d 8b [2] 66 8d [2] 7a 8a [2] 66 a5 }

  condition:
    any of them
}