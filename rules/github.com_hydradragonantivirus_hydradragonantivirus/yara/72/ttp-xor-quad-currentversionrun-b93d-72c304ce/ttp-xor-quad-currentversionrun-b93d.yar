rule TTP_XOR_QUAD_CurrentVersionRun_b93d {
  strings:
    $key_b93d = { ea 52 [2] ce 5c [2] e5 70 [2] cb 52 [2] df 49 [2] d0 53 [2] ce 4e [2] cc 4f [2] d7 49 [2] cb 4e [2] d7 61 }

  condition:
    any of them
}