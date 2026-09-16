rule TTP_XOR_QUAD_CurrentVersionRun_4ed2 {
  strings:
    $key_4ed2 = { 1d bd [2] 39 b3 [2] 12 9f [2] 3c bd [2] 28 a6 [2] 27 bc [2] 39 a1 [2] 3b a0 [2] 20 a6 [2] 3c a1 [2] 20 8e }

  condition:
    any of them
}