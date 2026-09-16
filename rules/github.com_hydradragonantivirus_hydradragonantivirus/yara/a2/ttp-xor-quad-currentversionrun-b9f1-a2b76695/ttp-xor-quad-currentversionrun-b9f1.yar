rule TTP_XOR_QUAD_CurrentVersionRun_b9f1 {
  strings:
    $key_b9f1 = { ea 9e [2] ce 90 [2] e5 bc [2] cb 9e [2] df 85 [2] d0 9f [2] ce 82 [2] cc 83 [2] d7 85 [2] cb 82 [2] d7 ad }

  condition:
    any of them
}