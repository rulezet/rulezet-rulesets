rule TTP_XOR_QUAD_CurrentVersionRun_b91d {
  strings:
    $key_b91d = { ea 72 [2] ce 7c [2] e5 50 [2] cb 72 [2] df 69 [2] d0 73 [2] ce 6e [2] cc 6f [2] d7 69 [2] cb 6e [2] d7 41 }

  condition:
    any of them
}