rule TTP_XOR_QUAD_CurrentVersionRun_b904 {
  strings:
    $key_b904 = { ea 6b [2] ce 65 [2] e5 49 [2] cb 6b [2] df 70 [2] d0 6a [2] ce 77 [2] cc 76 [2] d7 70 [2] cb 77 [2] d7 58 }

  condition:
    any of them
}