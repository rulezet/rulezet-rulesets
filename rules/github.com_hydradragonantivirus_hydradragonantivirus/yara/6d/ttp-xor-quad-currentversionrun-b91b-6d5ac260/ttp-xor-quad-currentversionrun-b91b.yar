rule TTP_XOR_QUAD_CurrentVersionRun_b91b {
  strings:
    $key_b91b = { ea 74 [2] ce 7a [2] e5 56 [2] cb 74 [2] df 6f [2] d0 75 [2] ce 68 [2] cc 69 [2] d7 6f [2] cb 68 [2] d7 47 }

  condition:
    any of them
}