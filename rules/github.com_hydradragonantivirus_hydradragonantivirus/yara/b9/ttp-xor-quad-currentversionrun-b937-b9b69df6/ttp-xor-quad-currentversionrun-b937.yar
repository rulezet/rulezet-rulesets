rule TTP_XOR_QUAD_CurrentVersionRun_b937 {
  strings:
    $key_b937 = { ea 58 [2] ce 56 [2] e5 7a [2] cb 58 [2] df 43 [2] d0 59 [2] ce 44 [2] cc 45 [2] d7 43 [2] cb 44 [2] d7 6b }

  condition:
    any of them
}