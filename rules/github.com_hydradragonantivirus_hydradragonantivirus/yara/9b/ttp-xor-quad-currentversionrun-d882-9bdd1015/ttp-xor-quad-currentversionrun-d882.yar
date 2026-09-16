rule TTP_XOR_QUAD_CurrentVersionRun_d882 {
  strings:
    $key_d882 = { 8b ed [2] af e3 [2] 84 cf [2] aa ed [2] be f6 [2] b1 ec [2] af f1 [2] ad f0 [2] b6 f6 [2] aa f1 [2] b6 de }

  condition:
    any of them
}