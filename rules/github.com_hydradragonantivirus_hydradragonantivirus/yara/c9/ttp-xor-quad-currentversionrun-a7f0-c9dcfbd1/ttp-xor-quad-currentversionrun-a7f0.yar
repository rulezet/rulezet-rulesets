rule TTP_XOR_QUAD_CurrentVersionRun_a7f0 {
  strings:
    $key_a7f0 = { f4 9f [2] d0 91 [2] fb bd [2] d5 9f [2] c1 84 [2] ce 9e [2] d0 83 [2] d2 82 [2] c9 84 [2] d5 83 [2] c9 ac }

  condition:
    any of them
}