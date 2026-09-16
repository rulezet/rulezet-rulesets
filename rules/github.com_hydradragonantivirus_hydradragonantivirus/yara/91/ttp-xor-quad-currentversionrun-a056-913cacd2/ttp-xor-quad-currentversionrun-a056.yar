rule TTP_XOR_QUAD_CurrentVersionRun_a056 {
  strings:
    $key_a056 = { f3 39 [2] d7 37 [2] fc 1b [2] d2 39 [2] c6 22 [2] c9 38 [2] d7 25 [2] d5 24 [2] ce 22 [2] d2 25 [2] ce 0a }

  condition:
    any of them
}