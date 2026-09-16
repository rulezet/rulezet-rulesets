rule TTP_XOR_QUAD_CurrentVersionRun_dd13 {
  strings:
    $key_dd13 = { 8e 7c [2] aa 72 [2] 81 5e [2] af 7c [2] bb 67 [2] b4 7d [2] aa 60 [2] a8 61 [2] b3 67 [2] af 60 [2] b3 4f }

  condition:
    any of them
}