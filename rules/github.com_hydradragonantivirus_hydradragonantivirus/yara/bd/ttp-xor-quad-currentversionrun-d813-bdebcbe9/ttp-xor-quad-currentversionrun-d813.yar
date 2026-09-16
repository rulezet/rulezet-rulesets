rule TTP_XOR_QUAD_CurrentVersionRun_d813 {
  strings:
    $key_d813 = { 8b 7c [2] af 72 [2] 84 5e [2] aa 7c [2] be 67 [2] b1 7d [2] af 60 [2] ad 61 [2] b6 67 [2] aa 60 [2] b6 4f }

  condition:
    any of them
}