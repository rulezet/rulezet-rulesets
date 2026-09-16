rule TTP_XOR_QUAD_CurrentVersionRun_b940 {
  strings:
    $key_b940 = { ea 2f [2] ce 21 [2] e5 0d [2] cb 2f [2] df 34 [2] d0 2e [2] ce 33 [2] cc 32 [2] d7 34 [2] cb 33 [2] d7 1c }

  condition:
    any of them
}