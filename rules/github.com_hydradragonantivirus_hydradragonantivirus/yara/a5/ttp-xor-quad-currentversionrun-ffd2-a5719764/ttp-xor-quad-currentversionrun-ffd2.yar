rule TTP_XOR_QUAD_CurrentVersionRun_ffd2 {
  strings:
    $key_ffd2 = { ac bd [2] 88 b3 [2] a3 9f [2] 8d bd [2] 99 a6 [2] 96 bc [2] 88 a1 [2] 8a a0 [2] 91 a6 [2] 8d a1 [2] 91 8e }

  condition:
    any of them
}