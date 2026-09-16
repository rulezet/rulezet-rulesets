rule TTP_XOR_QUAD_CurrentVersionRun_dd26 {
  strings:
    $key_dd26 = { 8e 49 [2] aa 47 [2] 81 6b [2] af 49 [2] bb 52 [2] b4 48 [2] aa 55 [2] a8 54 [2] b3 52 [2] af 55 [2] b3 7a }

  condition:
    any of them
}