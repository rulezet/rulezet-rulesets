rule TTP_XOR_QUAD_CurrentVersionRun_3804 {
  strings:
    $key_3804 = { 6b 6b [2] 4f 65 [2] 64 49 [2] 4a 6b [2] 5e 70 [2] 51 6a [2] 4f 77 [2] 4d 76 [2] 56 70 [2] 4a 77 [2] 56 58 }

  condition:
    any of them
}