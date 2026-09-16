rule TTP_XOR_QUAD_CurrentVersionRun_be0c {
  strings:
    $key_be0c = { ed 63 [2] c9 6d [2] e2 41 [2] cc 63 [2] d8 78 [2] d7 62 [2] c9 7f [2] cb 7e [2] d0 78 [2] cc 7f [2] d0 50 }

  condition:
    any of them
}