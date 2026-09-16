rule TTP_XOR_QUAD_CurrentVersionRun_ddf3 {
  strings:
    $key_ddf3 = { 8e 9c [2] aa 92 [2] 81 be [2] af 9c [2] bb 87 [2] b4 9d [2] aa 80 [2] a8 81 [2] b3 87 [2] af 80 [2] b3 af }

  condition:
    any of them
}