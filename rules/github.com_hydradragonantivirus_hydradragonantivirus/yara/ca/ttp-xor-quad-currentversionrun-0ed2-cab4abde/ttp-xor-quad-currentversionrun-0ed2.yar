rule TTP_XOR_QUAD_CurrentVersionRun_0ed2 {
  strings:
    $key_0ed2 = { 5d bd [2] 79 b3 [2] 52 9f [2] 7c bd [2] 68 a6 [2] 67 bc [2] 79 a1 [2] 7b a0 [2] 60 a6 [2] 7c a1 [2] 60 8e }

  condition:
    any of them
}