rule TTP_XOR_QUAD_CurrentVersionRun_3fd2 {
  strings:
    $key_3fd2 = { 6c bd [2] 48 b3 [2] 63 9f [2] 4d bd [2] 59 a6 [2] 56 bc [2] 48 a1 [2] 4a a0 [2] 51 a6 [2] 4d a1 [2] 51 8e }

  condition:
    any of them
}