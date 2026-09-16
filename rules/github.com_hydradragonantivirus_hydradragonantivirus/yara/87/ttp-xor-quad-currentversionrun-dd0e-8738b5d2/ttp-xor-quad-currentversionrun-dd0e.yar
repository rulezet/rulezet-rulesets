rule TTP_XOR_QUAD_CurrentVersionRun_dd0e {
  strings:
    $key_dd0e = { 8e 61 [2] aa 6f [2] 81 43 [2] af 61 [2] bb 7a [2] b4 60 [2] aa 7d [2] a8 7c [2] b3 7a [2] af 7d [2] b3 52 }

  condition:
    any of them
}