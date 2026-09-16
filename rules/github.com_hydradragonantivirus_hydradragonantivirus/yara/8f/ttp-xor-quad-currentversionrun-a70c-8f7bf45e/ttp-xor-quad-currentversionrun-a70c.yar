rule TTP_XOR_QUAD_CurrentVersionRun_a70c {
  strings:
    $key_a70c = { f4 63 [2] d0 6d [2] fb 41 [2] d5 63 [2] c1 78 [2] ce 62 [2] d0 7f [2] d2 7e [2] c9 78 [2] d5 7f [2] c9 50 }

  condition:
    any of them
}