rule TTP_XOR_QUAD_CurrentVersionRun_ebcd {
  strings:
    $key_ebcd = { b8 a2 [2] 9c ac [2] b7 80 [2] 99 a2 [2] 8d b9 [2] 82 a3 [2] 9c be [2] 9e bf [2] 85 b9 [2] 99 be [2] 85 91 }

  condition:
    any of them
}