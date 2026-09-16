rule TTP_XOR_QUAD_CurrentVersionRun_a701 {
  strings:
    $key_a701 = { f4 6e [2] d0 60 [2] fb 4c [2] d5 6e [2] c1 75 [2] ce 6f [2] d0 72 [2] d2 73 [2] c9 75 [2] d5 72 [2] c9 5d }

  condition:
    any of them
}