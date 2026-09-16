rule TTP_XOR_QUAD_CurrentVersionRun_a771 {
  strings:
    $key_a771 = { f4 1e [2] d0 10 [2] fb 3c [2] d5 1e [2] c1 05 [2] ce 1f [2] d0 02 [2] d2 03 [2] c9 05 [2] d5 02 [2] c9 2d }

  condition:
    any of them
}