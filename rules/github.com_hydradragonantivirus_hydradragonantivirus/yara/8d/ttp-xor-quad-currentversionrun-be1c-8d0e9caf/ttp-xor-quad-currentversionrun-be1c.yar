rule TTP_XOR_QUAD_CurrentVersionRun_be1c {
  strings:
    $key_be1c = { ed 73 [2] c9 7d [2] e2 51 [2] cc 73 [2] d8 68 [2] d7 72 [2] c9 6f [2] cb 6e [2] d0 68 [2] cc 6f [2] d0 40 }

  condition:
    any of them
}