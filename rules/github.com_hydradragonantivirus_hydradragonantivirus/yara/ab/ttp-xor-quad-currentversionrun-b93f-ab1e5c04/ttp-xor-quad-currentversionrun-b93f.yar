rule TTP_XOR_QUAD_CurrentVersionRun_b93f {
  strings:
    $key_b93f = { ea 50 [2] ce 5e [2] e5 72 [2] cb 50 [2] df 4b [2] d0 51 [2] ce 4c [2] cc 4d [2] d7 4b [2] cb 4c [2] d7 63 }

  condition:
    any of them
}