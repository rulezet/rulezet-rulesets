rule TTP_XOR_QUAD_CurrentVersionRun_be1f {
  strings:
    $key_be1f = { ed 70 [2] c9 7e [2] e2 52 [2] cc 70 [2] d8 6b [2] d7 71 [2] c9 6c [2] cb 6d [2] d0 6b [2] cc 6c [2] d0 43 }

  condition:
    any of them
}