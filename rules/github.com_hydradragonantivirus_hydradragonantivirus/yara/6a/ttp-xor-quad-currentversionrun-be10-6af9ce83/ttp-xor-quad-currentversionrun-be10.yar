rule TTP_XOR_QUAD_CurrentVersionRun_be10 {
  strings:
    $key_be10 = { ed 7f [2] c9 71 [2] e2 5d [2] cc 7f [2] d8 64 [2] d7 7e [2] c9 63 [2] cb 62 [2] d0 64 [2] cc 63 [2] d0 4c }

  condition:
    any of them
}