rule TTP_XOR_QUAD_CurrentVersionRun_5ed2 {
  strings:
    $key_5ed2 = { 0d bd [2] 29 b3 [2] 02 9f [2] 2c bd [2] 38 a6 [2] 37 bc [2] 29 a1 [2] 2b a0 [2] 30 a6 [2] 2c a1 [2] 30 8e }

  condition:
    any of them
}