rule TTP_XOR_QUAD_CurrentVersionRun_c104 {
  strings:
    $key_c104 = { 92 6b [2] b6 65 [2] 9d 49 [2] b3 6b [2] a7 70 [2] a8 6a [2] b6 77 [2] b4 76 [2] af 70 [2] b3 77 [2] af 58 }

  condition:
    any of them
}