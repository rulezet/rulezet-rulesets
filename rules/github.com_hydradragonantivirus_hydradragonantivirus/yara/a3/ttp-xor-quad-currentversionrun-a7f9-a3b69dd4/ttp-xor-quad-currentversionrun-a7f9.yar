rule TTP_XOR_QUAD_CurrentVersionRun_a7f9 {
  strings:
    $key_a7f9 = { f4 96 [2] d0 98 [2] fb b4 [2] d5 96 [2] c1 8d [2] ce 97 [2] d0 8a [2] d2 8b [2] c9 8d [2] d5 8a [2] c9 a5 }

  condition:
    any of them
}