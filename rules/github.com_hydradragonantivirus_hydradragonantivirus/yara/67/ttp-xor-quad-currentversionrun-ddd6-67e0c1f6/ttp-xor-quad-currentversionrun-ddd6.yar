rule TTP_XOR_QUAD_CurrentVersionRun_ddd6 {
  strings:
    $key_ddd6 = { 8e b9 [2] aa b7 [2] 81 9b [2] af b9 [2] bb a2 [2] b4 b8 [2] aa a5 [2] a8 a4 [2] b3 a2 [2] af a5 [2] b3 8a }

  condition:
    any of them
}