rule TTP_XOR_QUAD_CurrentVersionRun_beff {
  strings:
    $key_beff = { ed 90 [2] c9 9e [2] e2 b2 [2] cc 90 [2] d8 8b [2] d7 91 [2] c9 8c [2] cb 8d [2] d0 8b [2] cc 8c [2] d0 a3 }

  condition:
    any of them
}