rule TTP_XOR_QUAD_CurrentVersionRun_4fd2 {
  strings:
    $key_4fd2 = { 1c bd [2] 38 b3 [2] 13 9f [2] 3d bd [2] 29 a6 [2] 26 bc [2] 38 a1 [2] 3a a0 [2] 21 a6 [2] 3d a1 [2] 21 8e }

  condition:
    any of them
}