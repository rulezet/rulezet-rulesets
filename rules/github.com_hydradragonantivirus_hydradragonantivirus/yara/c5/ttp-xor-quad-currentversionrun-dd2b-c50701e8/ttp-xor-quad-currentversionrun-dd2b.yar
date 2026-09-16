rule TTP_XOR_QUAD_CurrentVersionRun_dd2b {
  strings:
    $key_dd2b = { 8e 44 [2] aa 4a [2] 81 66 [2] af 44 [2] bb 5f [2] b4 45 [2] aa 58 [2] a8 59 [2] b3 5f [2] af 58 [2] b3 77 }

  condition:
    any of them
}