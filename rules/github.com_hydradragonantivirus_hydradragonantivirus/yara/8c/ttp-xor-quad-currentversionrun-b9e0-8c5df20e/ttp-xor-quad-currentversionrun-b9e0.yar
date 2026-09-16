rule TTP_XOR_QUAD_CurrentVersionRun_b9e0 {
  strings:
    $key_b9e0 = { ea 8f [2] ce 81 [2] e5 ad [2] cb 8f [2] df 94 [2] d0 8e [2] ce 93 [2] cc 92 [2] d7 94 [2] cb 93 [2] d7 bc }

  condition:
    any of them
}