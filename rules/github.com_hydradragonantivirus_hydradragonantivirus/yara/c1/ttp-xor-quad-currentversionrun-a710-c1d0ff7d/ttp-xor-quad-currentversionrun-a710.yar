rule TTP_XOR_QUAD_CurrentVersionRun_a710 {
  strings:
    $key_a710 = { f4 7f [2] d0 71 [2] fb 5d [2] d5 7f [2] c1 64 [2] ce 7e [2] d0 63 [2] d2 62 [2] c9 64 [2] d5 63 [2] c9 4c }

  condition:
    any of them
}