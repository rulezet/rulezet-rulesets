rule TTP_XOR_QUAD_CurrentVersionRun_dd0b {
  strings:
    $key_dd0b = { 8e 64 [2] aa 6a [2] 81 46 [2] af 64 [2] bb 7f [2] b4 65 [2] aa 78 [2] a8 79 [2] b3 7f [2] af 78 [2] b3 57 }

  condition:
    any of them
}