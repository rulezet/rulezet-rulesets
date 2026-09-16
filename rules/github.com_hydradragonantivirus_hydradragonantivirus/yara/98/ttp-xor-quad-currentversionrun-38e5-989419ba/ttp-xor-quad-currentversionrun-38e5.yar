rule TTP_XOR_QUAD_CurrentVersionRun_38e5 {
  strings:
    $key_38e5 = { 6b 8a [2] 4f 84 [2] 64 a8 [2] 4a 8a [2] 5e 91 [2] 51 8b [2] 4f 96 [2] 4d 97 [2] 56 91 [2] 4a 96 [2] 56 b9 }

  condition:
    any of them
}