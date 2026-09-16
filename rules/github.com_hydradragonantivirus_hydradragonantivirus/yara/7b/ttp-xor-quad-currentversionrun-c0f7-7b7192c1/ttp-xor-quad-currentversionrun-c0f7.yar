rule TTP_XOR_QUAD_CurrentVersionRun_c0f7 {
  strings:
    $key_c0f7 = { 93 98 [2] b7 96 [2] 9c ba [2] b2 98 [2] a6 83 [2] a9 99 [2] b7 84 [2] b5 85 [2] ae 83 [2] b2 84 [2] ae ab }

  condition:
    any of them
}