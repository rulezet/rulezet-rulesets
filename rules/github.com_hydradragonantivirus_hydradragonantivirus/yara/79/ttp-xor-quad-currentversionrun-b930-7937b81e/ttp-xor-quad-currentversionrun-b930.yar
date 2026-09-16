rule TTP_XOR_QUAD_CurrentVersionRun_b930 {
  strings:
    $key_b930 = { ea 5f [2] ce 51 [2] e5 7d [2] cb 5f [2] df 44 [2] d0 5e [2] ce 43 [2] cc 42 [2] d7 44 [2] cb 43 [2] d7 6c }

  condition:
    any of them
}