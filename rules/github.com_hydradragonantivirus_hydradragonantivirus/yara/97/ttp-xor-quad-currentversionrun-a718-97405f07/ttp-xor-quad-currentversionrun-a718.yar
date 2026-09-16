rule TTP_XOR_QUAD_CurrentVersionRun_a718 {
  strings:
    $key_a718 = { f4 77 [2] d0 79 [2] fb 55 [2] d5 77 [2] c1 6c [2] ce 76 [2] d0 6b [2] d2 6a [2] c9 6c [2] d5 6b [2] c9 44 }

  condition:
    any of them
}