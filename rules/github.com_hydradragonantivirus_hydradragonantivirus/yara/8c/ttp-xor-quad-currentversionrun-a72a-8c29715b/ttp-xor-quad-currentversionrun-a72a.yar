rule TTP_XOR_QUAD_CurrentVersionRun_a72a {
  strings:
    $key_a72a = { f4 45 [2] d0 4b [2] fb 67 [2] d5 45 [2] c1 5e [2] ce 44 [2] d0 59 [2] d2 58 [2] c9 5e [2] d5 59 [2] c9 76 }

  condition:
    any of them
}