rule TTP_XOR_QUAD_CurrentVersionRun_b917 {
  strings:
    $key_b917 = { ea 78 [2] ce 76 [2] e5 5a [2] cb 78 [2] df 63 [2] d0 79 [2] ce 64 [2] cc 65 [2] d7 63 [2] cb 64 [2] d7 4b }

  condition:
    any of them
}