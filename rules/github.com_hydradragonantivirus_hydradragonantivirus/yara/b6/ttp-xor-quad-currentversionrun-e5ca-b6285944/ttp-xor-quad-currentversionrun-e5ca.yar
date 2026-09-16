rule TTP_XOR_QUAD_CurrentVersionRun_e5ca {
  strings:
    $key_e5ca = { b6 a5 [2] 92 ab [2] b9 87 [2] 97 a5 [2] 83 be [2] 8c a4 [2] 92 b9 [2] 90 b8 [2] 8b be [2] 97 b9 [2] 8b 96 }

  condition:
    any of them
}