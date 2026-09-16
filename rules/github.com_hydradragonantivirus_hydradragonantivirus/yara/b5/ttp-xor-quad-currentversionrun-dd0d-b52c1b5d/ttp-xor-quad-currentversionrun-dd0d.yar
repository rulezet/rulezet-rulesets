rule TTP_XOR_QUAD_CurrentVersionRun_dd0d {
  strings:
    $key_dd0d = { 8e 62 [2] aa 6c [2] 81 40 [2] af 62 [2] bb 79 [2] b4 63 [2] aa 7e [2] a8 7f [2] b3 79 [2] af 7e [2] b3 51 }

  condition:
    any of them
}