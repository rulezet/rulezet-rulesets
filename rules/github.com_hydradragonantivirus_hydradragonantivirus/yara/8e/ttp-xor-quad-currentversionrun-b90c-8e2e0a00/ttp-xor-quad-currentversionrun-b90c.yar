rule TTP_XOR_QUAD_CurrentVersionRun_b90c {
  strings:
    $key_b90c = { ea 63 [2] ce 6d [2] e5 41 [2] cb 63 [2] df 78 [2] d0 62 [2] ce 7f [2] cc 7e [2] d7 78 [2] cb 7f [2] d7 50 }

  condition:
    any of them
}