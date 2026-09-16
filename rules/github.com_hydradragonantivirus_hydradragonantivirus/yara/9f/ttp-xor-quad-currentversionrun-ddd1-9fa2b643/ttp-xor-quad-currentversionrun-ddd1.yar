rule TTP_XOR_QUAD_CurrentVersionRun_ddd1 {
  strings:
    $key_ddd1 = { 8e be [2] aa b0 [2] 81 9c [2] af be [2] bb a5 [2] b4 bf [2] aa a2 [2] a8 a3 [2] b3 a5 [2] af a2 [2] b3 8d }

  condition:
    any of them
}