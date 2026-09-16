rule TTP_XOR_QUAD_CurrentVersionRun_b9ea {
  strings:
    $key_b9ea = { ea 85 [2] ce 8b [2] e5 a7 [2] cb 85 [2] df 9e [2] d0 84 [2] ce 99 [2] cc 98 [2] d7 9e [2] cb 99 [2] d7 b6 }

  condition:
    any of them
}