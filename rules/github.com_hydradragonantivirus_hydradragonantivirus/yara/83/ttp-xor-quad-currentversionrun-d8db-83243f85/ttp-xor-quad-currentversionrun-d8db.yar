rule TTP_XOR_QUAD_CurrentVersionRun_d8db {
  strings:
    $key_d8db = { 8b b4 [2] af ba [2] 84 96 [2] aa b4 [2] be af [2] b1 b5 [2] af a8 [2] ad a9 [2] b6 af [2] aa a8 [2] b6 87 }

  condition:
    any of them
}