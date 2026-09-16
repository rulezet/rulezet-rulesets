rule TTP_XOR_QUAD_CurrentVersionRun_dd2d {
  strings:
    $key_dd2d = { 8e 42 [2] aa 4c [2] 81 60 [2] af 42 [2] bb 59 [2] b4 43 [2] aa 5e [2] a8 5f [2] b3 59 [2] af 5e [2] b3 71 }

  condition:
    any of them
}