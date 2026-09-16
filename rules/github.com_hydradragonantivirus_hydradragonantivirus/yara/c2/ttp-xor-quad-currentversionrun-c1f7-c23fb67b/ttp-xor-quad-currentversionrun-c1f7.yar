rule TTP_XOR_QUAD_CurrentVersionRun_c1f7 {
  strings:
    $key_c1f7 = { 92 98 [2] b6 96 [2] 9d ba [2] b3 98 [2] a7 83 [2] a8 99 [2] b6 84 [2] b4 85 [2] af 83 [2] b3 84 [2] af ab }

  condition:
    any of them
}