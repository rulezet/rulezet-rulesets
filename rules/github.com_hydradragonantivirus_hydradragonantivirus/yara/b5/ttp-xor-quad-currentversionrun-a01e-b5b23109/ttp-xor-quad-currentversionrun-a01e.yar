rule TTP_XOR_QUAD_CurrentVersionRun_a01e {
  strings:
    $key_a01e = { f3 71 [2] d7 7f [2] fc 53 [2] d2 71 [2] c6 6a [2] c9 70 [2] d7 6d [2] d5 6c [2] ce 6a [2] d2 6d [2] ce 42 }

  condition:
    any of them
}