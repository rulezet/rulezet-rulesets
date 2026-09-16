rule TTP_XOR_QUAD_CurrentVersionRun_a0fd {
  strings:
    $key_a0fd = { f3 92 [2] d7 9c [2] fc b0 [2] d2 92 [2] c6 89 [2] c9 93 [2] d7 8e [2] d5 8f [2] ce 89 [2] d2 8e [2] ce a1 }

  condition:
    any of them
}