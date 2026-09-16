rule TTP_XOR_QUAD_CurrentVersionRun_c483 {
  strings:
    $key_c483 = { 97 ec [2] b3 e2 [2] 98 ce [2] b6 ec [2] a2 f7 [2] ad ed [2] b3 f0 [2] b1 f1 [2] aa f7 [2] b6 f0 [2] aa df }

  condition:
    any of them
}