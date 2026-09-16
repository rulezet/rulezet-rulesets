rule TTP_XOR_QUAD_CurrentVersionRun_7fd2 {
  strings:
    $key_7fd2 = { 2c bd [2] 08 b3 [2] 23 9f [2] 0d bd [2] 19 a6 [2] 16 bc [2] 08 a1 [2] 0a a0 [2] 11 a6 [2] 0d a1 [2] 11 8e }

  condition:
    any of them
}