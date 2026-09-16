rule TTP_XOR_QUAD_CurrentVersionRun_a03c {
  strings:
    $key_a03c = { f3 53 [2] d7 5d [2] fc 71 [2] d2 53 [2] c6 48 [2] c9 52 [2] d7 4f [2] d5 4e [2] ce 48 [2] d2 4f [2] ce 60 }

  condition:
    any of them
}