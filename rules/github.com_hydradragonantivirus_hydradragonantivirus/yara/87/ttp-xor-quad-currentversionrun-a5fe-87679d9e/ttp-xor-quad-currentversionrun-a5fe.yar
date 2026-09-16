rule TTP_XOR_QUAD_CurrentVersionRun_a5fe {
  strings:
    $key_a5fe = { f6 91 [2] d2 9f [2] f9 b3 [2] d7 91 [2] c3 8a [2] cc 90 [2] d2 8d [2] d0 8c [2] cb 8a [2] d7 8d [2] cb a2 }

  condition:
    any of them
}