rule TTP_XOR_QUAD_CurrentVersionRun_a7fe {
  strings:
    $key_a7fe = { f4 91 [2] d0 9f [2] fb b3 [2] d5 91 [2] c1 8a [2] ce 90 [2] d0 8d [2] d2 8c [2] c9 8a [2] d5 8d [2] c9 a2 }

  condition:
    any of them
}