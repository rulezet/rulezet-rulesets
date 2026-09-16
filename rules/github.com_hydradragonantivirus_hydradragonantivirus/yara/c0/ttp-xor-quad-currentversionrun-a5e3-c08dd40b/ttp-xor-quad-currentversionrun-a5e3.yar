rule TTP_XOR_QUAD_CurrentVersionRun_a5e3 {
  strings:
    $key_a5e3 = { f6 8c [2] d2 82 [2] f9 ae [2] d7 8c [2] c3 97 [2] cc 8d [2] d2 90 [2] d0 91 [2] cb 97 [2] d7 90 [2] cb bf }

  condition:
    any of them
}