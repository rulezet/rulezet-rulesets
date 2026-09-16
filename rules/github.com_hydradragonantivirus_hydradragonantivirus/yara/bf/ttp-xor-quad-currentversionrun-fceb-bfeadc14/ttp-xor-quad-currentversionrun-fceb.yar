rule TTP_XOR_QUAD_CurrentVersionRun_fceb {
  strings:
    $key_fceb = { af 84 [2] 8b 8a [2] a0 a6 [2] 8e 84 [2] 9a 9f [2] 95 85 [2] 8b 98 [2] 89 99 [2] 92 9f [2] 8e 98 [2] 92 b7 }

  condition:
    any of them
}