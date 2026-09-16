rule TTP_XOR_QUAD_CurrentVersionRun_a712 {
  strings:
    $key_a712 = { f4 7d [2] d0 73 [2] fb 5f [2] d5 7d [2] c1 66 [2] ce 7c [2] d0 61 [2] d2 60 [2] c9 66 [2] d5 61 [2] c9 4e }

  condition:
    any of them
}