rule TTP_XOR_QUAD_CurrentVersionRun_fcf8 {
  strings:
    $key_fcf8 = { af 97 [2] 8b 99 [2] a0 b5 [2] 8e 97 [2] 9a 8c [2] 95 96 [2] 8b 8b [2] 89 8a [2] 92 8c [2] 8e 8b [2] 92 a4 }

  condition:
    any of them
}