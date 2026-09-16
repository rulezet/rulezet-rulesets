rule TTP_XOR_QUAD_CurrentVersionRun_0813 {
  strings:
    $key_0813 = { 5b 7c [2] 7f 72 [2] 54 5e [2] 7a 7c [2] 6e 67 [2] 61 7d [2] 7f 60 [2] 7d 61 [2] 66 67 [2] 7a 60 [2] 66 4f }

  condition:
    any of them
}