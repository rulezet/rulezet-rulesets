rule TTP_XOR_QUAD_CurrentVersionRun_b968 {
  strings:
    $key_b968 = { ea 07 [2] ce 09 [2] e5 25 [2] cb 07 [2] df 1c [2] d0 06 [2] ce 1b [2] cc 1a [2] d7 1c [2] cb 1b [2] d7 34 }

  condition:
    any of them
}