rule TTP_XOR_QUAD_CurrentVersionRun_b900 {
  strings:
    $key_b900 = { ea 6f [2] ce 61 [2] e5 4d [2] cb 6f [2] df 74 [2] d0 6e [2] ce 73 [2] cc 72 [2] d7 74 [2] cb 73 [2] d7 5c }

  condition:
    any of them
}