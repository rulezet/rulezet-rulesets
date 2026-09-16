rule TTP_XOR_QUAD_CurrentVersionRun_dd2a {
  strings:
    $key_dd2a = { 8e 45 [2] aa 4b [2] 81 67 [2] af 45 [2] bb 5e [2] b4 44 [2] aa 59 [2] a8 58 [2] b3 5e [2] af 59 [2] b3 76 }

  condition:
    any of them
}