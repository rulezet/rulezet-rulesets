rule TTP_XOR_QUAD_CurrentVersionRun_a0f9 {
  strings:
    $key_a0f9 = { f3 96 [2] d7 98 [2] fc b4 [2] d2 96 [2] c6 8d [2] c9 97 [2] d7 8a [2] d5 8b [2] ce 8d [2] d2 8a [2] ce a5 }

  condition:
    any of them
}