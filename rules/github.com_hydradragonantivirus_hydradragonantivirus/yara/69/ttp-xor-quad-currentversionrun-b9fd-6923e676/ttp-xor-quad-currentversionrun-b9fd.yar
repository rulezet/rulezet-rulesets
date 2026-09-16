rule TTP_XOR_QUAD_CurrentVersionRun_b9fd {
  strings:
    $key_b9fd = { ea 92 [2] ce 9c [2] e5 b0 [2] cb 92 [2] df 89 [2] d0 93 [2] ce 8e [2] cc 8f [2] d7 89 [2] cb 8e [2] d7 a1 }

  condition:
    any of them
}