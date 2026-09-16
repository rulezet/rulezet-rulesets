rule TTP_XOR_QUAD_CurrentVersionRun_b9ee {
  strings:
    $key_b9ee = { ea 81 [2] ce 8f [2] e5 a3 [2] cb 81 [2] df 9a [2] d0 80 [2] ce 9d [2] cc 9c [2] d7 9a [2] cb 9d [2] d7 b2 }

  condition:
    any of them
}