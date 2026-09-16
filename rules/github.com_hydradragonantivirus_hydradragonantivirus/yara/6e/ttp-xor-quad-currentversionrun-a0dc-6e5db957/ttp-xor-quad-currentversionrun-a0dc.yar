rule TTP_XOR_QUAD_CurrentVersionRun_a0dc {
  strings:
    $key_a0dc = { f3 b3 [2] d7 bd [2] fc 91 [2] d2 b3 [2] c6 a8 [2] c9 b2 [2] d7 af [2] d5 ae [2] ce a8 [2] d2 af [2] ce 80 }

  condition:
    any of them
}