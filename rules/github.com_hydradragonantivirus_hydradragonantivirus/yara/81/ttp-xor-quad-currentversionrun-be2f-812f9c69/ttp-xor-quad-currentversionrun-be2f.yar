rule TTP_XOR_QUAD_CurrentVersionRun_be2f {
  strings:
    $key_be2f = { ed 40 [2] c9 4e [2] e2 62 [2] cc 40 [2] d8 5b [2] d7 41 [2] c9 5c [2] cb 5d [2] d0 5b [2] cc 5c [2] d0 73 }

  condition:
    any of them
}