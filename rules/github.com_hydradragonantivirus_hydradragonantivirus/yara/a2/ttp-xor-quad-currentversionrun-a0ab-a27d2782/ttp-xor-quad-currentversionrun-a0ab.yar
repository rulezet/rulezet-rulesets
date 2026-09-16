rule TTP_XOR_QUAD_CurrentVersionRun_a0ab {
  strings:
    $key_a0ab = { f3 c4 [2] d7 ca [2] fc e6 [2] d2 c4 [2] c6 df [2] c9 c5 [2] d7 d8 [2] d5 d9 [2] ce df [2] d2 d8 [2] ce f7 }

  condition:
    any of them
}