rule TTP_XOR_QUAD_CurrentVersionRun_f8ca {
  strings:
    $key_f8ca = { ab a5 [2] 8f ab [2] a4 87 [2] 8a a5 [2] 9e be [2] 91 a4 [2] 8f b9 [2] 8d b8 [2] 96 be [2] 8a b9 [2] 96 96 }

  condition:
    any of them
}