rule TTP_XOR_QUAD_CurrentVersionRun_be20 {
  strings:
    $key_be20 = { ed 4f [2] c9 41 [2] e2 6d [2] cc 4f [2] d8 54 [2] d7 4e [2] c9 53 [2] cb 52 [2] d0 54 [2] cc 53 [2] d0 7c }

  condition:
    any of them
}