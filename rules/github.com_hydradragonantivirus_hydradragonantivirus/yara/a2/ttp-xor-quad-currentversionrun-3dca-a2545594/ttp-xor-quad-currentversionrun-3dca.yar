rule TTP_XOR_QUAD_CurrentVersionRun_3dca {
  strings:
    $key_3dca = { 6e a5 [2] 4a ab [2] 61 87 [2] 4f a5 [2] 5b be [2] 54 a4 [2] 4a b9 [2] 48 b8 [2] 53 be [2] 4f b9 [2] 53 96 }

  condition:
    any of them
}