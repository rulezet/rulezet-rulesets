rule TTP_XOR_QUAD_CurrentVersionRun_b961 {
  strings:
    $key_b961 = { ea 0e [2] ce 00 [2] e5 2c [2] cb 0e [2] df 15 [2] d0 0f [2] ce 12 [2] cc 13 [2] d7 15 [2] cb 12 [2] d7 3d }

  condition:
    any of them
}