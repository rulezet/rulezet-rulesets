rule TTP_XOR_QUAD_CurrentVersionRun_be3c {
  strings:
    $key_be3c = { ed 53 [2] c9 5d [2] e2 71 [2] cc 53 [2] d8 48 [2] d7 52 [2] c9 4f [2] cb 4e [2] d0 48 [2] cc 4f [2] d0 60 }

  condition:
    any of them
}