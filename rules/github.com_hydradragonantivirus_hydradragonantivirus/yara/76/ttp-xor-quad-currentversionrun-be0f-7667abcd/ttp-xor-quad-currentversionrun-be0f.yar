rule TTP_XOR_QUAD_CurrentVersionRun_be0f {
  strings:
    $key_be0f = { ed 60 [2] c9 6e [2] e2 42 [2] cc 60 [2] d8 7b [2] d7 61 [2] c9 7c [2] cb 7d [2] d0 7b [2] cc 7c [2] d0 53 }

  condition:
    any of them
}