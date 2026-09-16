rule TTP_XOR_QUAD_CurrentVersionRun_398c {
  strings:
    $key_398c = { 6a e3 [2] 4e ed [2] 65 c1 [2] 4b e3 [2] 5f f8 [2] 50 e2 [2] 4e ff [2] 4c fe [2] 57 f8 [2] 4b ff [2] 57 d0 }

  condition:
    any of them
}