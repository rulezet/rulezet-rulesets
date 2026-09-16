rule TTP_XOR_QUAD_CurrentVersionRun_0fd2 {
  strings:
    $key_0fd2 = { 5c bd [2] 78 b3 [2] 53 9f [2] 7d bd [2] 69 a6 [2] 66 bc [2] 78 a1 [2] 7a a0 [2] 61 a6 [2] 7d a1 [2] 61 8e }

  condition:
    any of them
}