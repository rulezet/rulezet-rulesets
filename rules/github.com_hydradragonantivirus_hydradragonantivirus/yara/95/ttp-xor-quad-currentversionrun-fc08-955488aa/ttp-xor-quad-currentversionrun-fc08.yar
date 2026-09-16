rule TTP_XOR_QUAD_CurrentVersionRun_fc08 {
  strings:
    $key_fc08 = { af 67 [2] 8b 69 [2] a0 45 [2] 8e 67 [2] 9a 7c [2] 95 66 [2] 8b 7b [2] 89 7a [2] 92 7c [2] 8e 7b [2] 92 54 }

  condition:
    any of them
}