rule TTP_XOR_QUAD_CurrentVersionRun_a50d {
  strings:
    $key_a50d = { f6 62 [2] d2 6c [2] f9 40 [2] d7 62 [2] c3 79 [2] cc 63 [2] d2 7e [2] d0 7f [2] cb 79 [2] d7 7e [2] cb 51 }

  condition:
    any of them
}