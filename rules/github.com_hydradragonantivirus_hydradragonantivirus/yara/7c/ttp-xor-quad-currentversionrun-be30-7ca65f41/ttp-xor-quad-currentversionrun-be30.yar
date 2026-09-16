rule TTP_XOR_QUAD_CurrentVersionRun_be30 {
  strings:
    $key_be30 = { ed 5f [2] c9 51 [2] e2 7d [2] cc 5f [2] d8 44 [2] d7 5e [2] c9 43 [2] cb 42 [2] d0 44 [2] cc 43 [2] d0 6c }

  condition:
    any of them
}