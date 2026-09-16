rule TTP_XOR_QUAD_CurrentVersionRun_b91c {
  strings:
    $key_b91c = { ea 73 [2] ce 7d [2] e5 51 [2] cb 73 [2] df 68 [2] d0 72 [2] ce 6f [2] cc 6e [2] d7 68 [2] cb 6f [2] d7 40 }

  condition:
    any of them
}