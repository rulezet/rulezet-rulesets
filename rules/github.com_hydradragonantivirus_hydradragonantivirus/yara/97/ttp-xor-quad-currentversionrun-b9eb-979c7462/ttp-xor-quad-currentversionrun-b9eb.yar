rule TTP_XOR_QUAD_CurrentVersionRun_b9eb {
  strings:
    $key_b9eb = { ea 84 [2] ce 8a [2] e5 a6 [2] cb 84 [2] df 9f [2] d0 85 [2] ce 98 [2] cc 99 [2] d7 9f [2] cb 98 [2] d7 b7 }

  condition:
    any of them
}