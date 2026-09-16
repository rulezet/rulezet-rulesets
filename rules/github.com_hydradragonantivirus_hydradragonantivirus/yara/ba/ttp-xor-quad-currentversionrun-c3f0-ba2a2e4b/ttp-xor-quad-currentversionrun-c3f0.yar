rule TTP_XOR_QUAD_CurrentVersionRun_c3f0 {
  strings:
    $key_c3f0 = { 90 9f [2] b4 91 [2] 9f bd [2] b1 9f [2] a5 84 [2] aa 9e [2] b4 83 [2] b6 82 [2] ad 84 [2] b1 83 [2] ad ac }

  condition:
    any of them
}