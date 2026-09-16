rule TTP_XOR_QUAD_CurrentVersionRun_b9f6 {
  strings:
    $key_b9f6 = { ea 99 [2] ce 97 [2] e5 bb [2] cb 99 [2] df 82 [2] d0 98 [2] ce 85 [2] cc 84 [2] d7 82 [2] cb 85 [2] d7 aa }

  condition:
    any of them
}