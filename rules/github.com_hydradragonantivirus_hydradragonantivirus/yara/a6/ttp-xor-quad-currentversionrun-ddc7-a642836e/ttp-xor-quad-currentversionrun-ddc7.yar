rule TTP_XOR_QUAD_CurrentVersionRun_ddc7 {
  strings:
    $key_ddc7 = { 8e a8 [2] aa a6 [2] 81 8a [2] af a8 [2] bb b3 [2] b4 a9 [2] aa b4 [2] a8 b5 [2] b3 b3 [2] af b4 [2] b3 9b }

  condition:
    any of them
}