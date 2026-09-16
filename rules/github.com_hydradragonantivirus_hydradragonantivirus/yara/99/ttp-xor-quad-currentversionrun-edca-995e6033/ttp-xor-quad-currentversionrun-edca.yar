rule TTP_XOR_QUAD_CurrentVersionRun_edca {
  strings:
    $key_edca = { be a5 [2] 9a ab [2] b1 87 [2] 9f a5 [2] 8b be [2] 84 a4 [2] 9a b9 [2] 98 b8 [2] 83 be [2] 9f b9 [2] 83 96 }

  condition:
    any of them
}