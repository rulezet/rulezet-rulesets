rule TTP_XOR_QUAD_CurrentVersionRun_38f8 {
  strings:
    $key_38f8 = { 6b 97 [2] 4f 99 [2] 64 b5 [2] 4a 97 [2] 5e 8c [2] 51 96 [2] 4f 8b [2] 4d 8a [2] 56 8c [2] 4a 8b [2] 56 a4 }

  condition:
    any of them
}