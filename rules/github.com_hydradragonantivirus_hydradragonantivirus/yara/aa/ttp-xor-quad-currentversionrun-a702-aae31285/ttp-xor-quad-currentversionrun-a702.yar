rule TTP_XOR_QUAD_CurrentVersionRun_a702 {
  strings:
    $key_a702 = { f4 6d [2] d0 63 [2] fb 4f [2] d5 6d [2] c1 76 [2] ce 6c [2] d0 71 [2] d2 70 [2] c9 76 [2] d5 71 [2] c9 5e }

  condition:
    any of them
}