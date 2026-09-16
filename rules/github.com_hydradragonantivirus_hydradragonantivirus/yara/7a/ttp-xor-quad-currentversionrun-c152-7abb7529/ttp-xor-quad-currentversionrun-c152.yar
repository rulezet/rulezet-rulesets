rule TTP_XOR_QUAD_CurrentVersionRun_c152 {
  strings:
    $key_c152 = { 92 3d [2] b6 33 [2] 9d 1f [2] b3 3d [2] a7 26 [2] a8 3c [2] b6 21 [2] b4 20 [2] af 26 [2] b3 21 [2] af 0e }

  condition:
    any of them
}