rule TTP_XOR_QUAD_CurrentVersionRun_c498 {
  strings:
    $key_c498 = { 97 f7 [2] b3 f9 [2] 98 d5 [2] b6 f7 [2] a2 ec [2] ad f6 [2] b3 eb [2] b1 ea [2] aa ec [2] b6 eb [2] aa c4 }

  condition:
    any of them
}