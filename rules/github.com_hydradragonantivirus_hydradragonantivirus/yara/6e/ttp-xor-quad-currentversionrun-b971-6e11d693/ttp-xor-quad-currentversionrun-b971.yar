rule TTP_XOR_QUAD_CurrentVersionRun_b971 {
  strings:
    $key_b971 = { ea 1e [2] ce 10 [2] e5 3c [2] cb 1e [2] df 05 [2] d0 1f [2] ce 02 [2] cc 03 [2] d7 05 [2] cb 02 [2] d7 2d }

  condition:
    any of them
}