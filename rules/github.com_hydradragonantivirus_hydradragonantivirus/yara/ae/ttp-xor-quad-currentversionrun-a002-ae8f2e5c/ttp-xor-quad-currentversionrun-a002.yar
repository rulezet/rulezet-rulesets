rule TTP_XOR_QUAD_CurrentVersionRun_a002 {
  strings:
    $key_a002 = { f3 6d [2] d7 63 [2] fc 4f [2] d2 6d [2] c6 76 [2] c9 6c [2] d7 71 [2] d5 70 [2] ce 76 [2] d2 71 [2] ce 5e }

  condition:
    any of them
}