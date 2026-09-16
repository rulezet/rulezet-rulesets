rule TTP_XOR_QUAD_CurrentVersionRun_eed0 {
  strings:
    $key_eed0 = { bd bf [2] 99 b1 [2] b2 9d [2] 9c bf [2] 88 a4 [2] 87 be [2] 99 a3 [2] 9b a2 [2] 80 a4 [2] 9c a3 [2] 80 8c }

  condition:
    any of them
}