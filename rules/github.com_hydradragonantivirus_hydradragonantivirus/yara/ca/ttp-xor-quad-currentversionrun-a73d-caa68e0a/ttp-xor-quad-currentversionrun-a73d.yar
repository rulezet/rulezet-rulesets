rule TTP_XOR_QUAD_CurrentVersionRun_a73d {
  strings:
    $key_a73d = { f4 52 [2] d0 5c [2] fb 70 [2] d5 52 [2] c1 49 [2] ce 53 [2] d0 4e [2] d2 4f [2] c9 49 [2] d5 4e [2] c9 61 }

  condition:
    any of them
}