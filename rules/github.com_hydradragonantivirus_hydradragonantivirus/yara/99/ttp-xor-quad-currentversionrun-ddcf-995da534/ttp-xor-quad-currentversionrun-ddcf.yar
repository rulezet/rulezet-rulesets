rule TTP_XOR_QUAD_CurrentVersionRun_ddcf {
  strings:
    $key_ddcf = { 8e a0 [2] aa ae [2] 81 82 [2] af a0 [2] bb bb [2] b4 a1 [2] aa bc [2] a8 bd [2] b3 bb [2] af bc [2] b3 93 }

  condition:
    any of them
}