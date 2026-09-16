rule TTP_XOR_QUAD_CurrentVersionRun_a76d {
  strings:
    $key_a76d = { f4 02 [2] d0 0c [2] fb 20 [2] d5 02 [2] c1 19 [2] ce 03 [2] d0 1e [2] d2 1f [2] c9 19 [2] d5 1e [2] c9 31 }

  condition:
    any of them
}