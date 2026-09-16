rule TTP_XOR_QUAD_CurrentVersionRun_fcf9 {
  strings:
    $key_fcf9 = { af 96 [2] 8b 98 [2] a0 b4 [2] 8e 96 [2] 9a 8d [2] 95 97 [2] 8b 8a [2] 89 8b [2] 92 8d [2] 8e 8a [2] 92 a5 }

  condition:
    any of them
}