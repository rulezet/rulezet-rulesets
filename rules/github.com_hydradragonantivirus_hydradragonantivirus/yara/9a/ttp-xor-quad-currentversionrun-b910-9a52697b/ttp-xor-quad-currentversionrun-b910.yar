rule TTP_XOR_QUAD_CurrentVersionRun_b910 {
  strings:
    $key_b910 = { ea 7f [2] ce 71 [2] e5 5d [2] cb 7f [2] df 64 [2] d0 7e [2] ce 63 [2] cc 62 [2] d7 64 [2] cb 63 [2] d7 4c }

  condition:
    any of them
}