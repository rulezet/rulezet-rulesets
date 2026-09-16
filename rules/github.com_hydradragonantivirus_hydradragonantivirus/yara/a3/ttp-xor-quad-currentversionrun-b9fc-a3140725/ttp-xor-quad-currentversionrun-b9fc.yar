rule TTP_XOR_QUAD_CurrentVersionRun_b9fc {
  strings:
    $key_b9fc = { ea 93 [2] ce 9d [2] e5 b1 [2] cb 93 [2] df 88 [2] d0 92 [2] ce 8f [2] cc 8e [2] d7 88 [2] cb 8f [2] d7 a0 }

  condition:
    any of them
}