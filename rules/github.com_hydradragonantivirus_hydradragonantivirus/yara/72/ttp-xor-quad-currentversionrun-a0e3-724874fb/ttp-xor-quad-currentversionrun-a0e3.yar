rule TTP_XOR_QUAD_CurrentVersionRun_a0e3 {
  strings:
    $key_a0e3 = { f3 8c [2] d7 82 [2] fc ae [2] d2 8c [2] c6 97 [2] c9 8d [2] d7 90 [2] d5 91 [2] ce 97 [2] d2 90 [2] ce bf }

  condition:
    any of them
}