rule TTP_XOR_QUAD_CurrentVersionRun_c135 {
  strings:
    $key_c135 = { 92 5a [2] b6 54 [2] 9d 78 [2] b3 5a [2] a7 41 [2] a8 5b [2] b6 46 [2] b4 47 [2] af 41 [2] b3 46 [2] af 69 }

  condition:
    any of them
}