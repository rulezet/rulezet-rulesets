rule TTP_XOR_QUAD_CurrentVersionRun_b94f {
  strings:
    $key_b94f = { ea 20 [2] ce 2e [2] e5 02 [2] cb 20 [2] df 3b [2] d0 21 [2] ce 3c [2] cc 3d [2] d7 3b [2] cb 3c [2] d7 13 }

  condition:
    any of them
}