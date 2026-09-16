rule TTP_XOR_QUAD_CurrentVersionRun_b93a {
  strings:
    $key_b93a = { ea 55 [2] ce 5b [2] e5 77 [2] cb 55 [2] df 4e [2] d0 54 [2] ce 49 [2] cc 48 [2] d7 4e [2] cb 49 [2] d7 66 }

  condition:
    any of them
}