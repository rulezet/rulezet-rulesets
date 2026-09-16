rule TTP_XOR_QUAD_CurrentVersionRun_b918 {
  strings:
    $key_b918 = { ea 77 [2] ce 79 [2] e5 55 [2] cb 77 [2] df 6c [2] d0 76 [2] ce 6b [2] cc 6a [2] d7 6c [2] cb 6b [2] d7 44 }

  condition:
    any of them
}