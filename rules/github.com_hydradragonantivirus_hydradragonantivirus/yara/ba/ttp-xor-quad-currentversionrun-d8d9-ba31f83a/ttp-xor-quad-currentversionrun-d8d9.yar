rule TTP_XOR_QUAD_CurrentVersionRun_d8d9 {
  strings:
    $key_d8d9 = { 8b b6 [2] af b8 [2] 84 94 [2] aa b6 [2] be ad [2] b1 b7 [2] af aa [2] ad ab [2] b6 ad [2] aa aa [2] b6 85 }

  condition:
    any of them
}