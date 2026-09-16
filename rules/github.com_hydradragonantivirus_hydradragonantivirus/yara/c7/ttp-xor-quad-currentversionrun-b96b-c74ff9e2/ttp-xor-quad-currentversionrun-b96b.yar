rule TTP_XOR_QUAD_CurrentVersionRun_b96b {
  strings:
    $key_b96b = { ea 04 [2] ce 0a [2] e5 26 [2] cb 04 [2] df 1f [2] d0 05 [2] ce 18 [2] cc 19 [2] d7 1f [2] cb 18 [2] d7 37 }

  condition:
    any of them
}