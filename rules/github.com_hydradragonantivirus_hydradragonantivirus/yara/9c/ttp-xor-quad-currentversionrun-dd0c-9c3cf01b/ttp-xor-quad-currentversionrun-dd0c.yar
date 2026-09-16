rule TTP_XOR_QUAD_CurrentVersionRun_dd0c {
  strings:
    $key_dd0c = { 8e 63 [2] aa 6d [2] 81 41 [2] af 63 [2] bb 78 [2] b4 62 [2] aa 7f [2] a8 7e [2] b3 78 [2] af 7f [2] b3 50 }

  condition:
    any of them
}