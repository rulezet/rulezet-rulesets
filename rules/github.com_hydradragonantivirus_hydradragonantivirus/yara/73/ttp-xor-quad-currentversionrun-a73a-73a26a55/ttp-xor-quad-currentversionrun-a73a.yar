rule TTP_XOR_QUAD_CurrentVersionRun_a73a {
  strings:
    $key_a73a = { f4 55 [2] d0 5b [2] fb 77 [2] d5 55 [2] c1 4e [2] ce 54 [2] d0 49 [2] d2 48 [2] c9 4e [2] d5 49 [2] c9 66 }

  condition:
    any of them
}