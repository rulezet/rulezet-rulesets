rule TTP_XOR_QUAD_CurrentVersionRun_a098 {
  strings:
    $key_a098 = { f3 f7 [2] d7 f9 [2] fc d5 [2] d2 f7 [2] c6 ec [2] c9 f6 [2] d7 eb [2] d5 ea [2] ce ec [2] d2 eb [2] ce c4 }

  condition:
    any of them
}