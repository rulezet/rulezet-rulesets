rule TTP_XOR_QUAD_CurrentVersionRun_ddf1 {
  strings:
    $key_ddf1 = { 8e 9e [2] aa 90 [2] 81 bc [2] af 9e [2] bb 85 [2] b4 9f [2] aa 82 [2] a8 83 [2] b3 85 [2] af 82 [2] b3 ad }

  condition:
    any of them
}