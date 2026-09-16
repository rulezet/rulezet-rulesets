rule TTP_XOR_QUAD_CurrentVersionRun_a53a {
  strings:
    $key_a53a = { f6 55 [2] d2 5b [2] f9 77 [2] d7 55 [2] c3 4e [2] cc 54 [2] d2 49 [2] d0 48 [2] cb 4e [2] d7 49 [2] cb 66 }

  condition:
    any of them
}