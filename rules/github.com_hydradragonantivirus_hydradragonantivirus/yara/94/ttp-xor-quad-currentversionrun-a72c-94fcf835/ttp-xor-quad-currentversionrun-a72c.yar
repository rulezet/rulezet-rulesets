rule TTP_XOR_QUAD_CurrentVersionRun_a72c {
  strings:
    $key_a72c = { f4 43 [2] d0 4d [2] fb 61 [2] d5 43 [2] c1 58 [2] ce 42 [2] d0 5f [2] d2 5e [2] c9 58 [2] d5 5f [2] c9 70 }

  condition:
    any of them
}