rule TTP_XOR_QUAD_CurrentVersionRun_ddfd {
  strings:
    $key_ddfd = { 8e 92 [2] aa 9c [2] 81 b0 [2] af 92 [2] bb 89 [2] b4 93 [2] aa 8e [2] a8 8f [2] b3 89 [2] af 8e [2] b3 a1 }

  condition:
    any of them
}