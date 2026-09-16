rule TTP_XOR_QUAD_CurrentVersionRun_c102 {
  strings:
    $key_c102 = { 92 6d [2] b6 63 [2] 9d 4f [2] b3 6d [2] a7 76 [2] a8 6c [2] b6 71 [2] b4 70 [2] af 76 [2] b3 71 [2] af 5e }

  condition:
    any of them
}