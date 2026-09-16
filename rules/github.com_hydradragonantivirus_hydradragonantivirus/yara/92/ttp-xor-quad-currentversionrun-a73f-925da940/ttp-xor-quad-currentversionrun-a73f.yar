rule TTP_XOR_QUAD_CurrentVersionRun_a73f {
  strings:
    $key_a73f = { f4 50 [2] d0 5e [2] fb 72 [2] d5 50 [2] c1 4b [2] ce 51 [2] d0 4c [2] d2 4d [2] c9 4b [2] d5 4c [2] c9 63 }

  condition:
    any of them
}