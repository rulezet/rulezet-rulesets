rule TTP_XOR_QUAD_CurrentVersionRun_b064 {
  strings:
    $key_b064 = { e3 0b [2] c7 05 [2] ec 29 [2] c2 0b [2] d6 10 [2] d9 0a [2] c7 17 [2] c5 16 [2] de 10 [2] c2 17 [2] de 38 }

  condition:
    any of them
}