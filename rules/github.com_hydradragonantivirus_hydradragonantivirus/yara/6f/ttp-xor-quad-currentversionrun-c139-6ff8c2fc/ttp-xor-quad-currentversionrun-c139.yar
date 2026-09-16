rule TTP_XOR_QUAD_CurrentVersionRun_c139 {
  strings:
    $key_c139 = { 92 56 [2] b6 58 [2] 9d 74 [2] b3 56 [2] a7 4d [2] a8 57 [2] b6 4a [2] b4 4b [2] af 4d [2] b3 4a [2] af 65 }

  condition:
    any of them
}