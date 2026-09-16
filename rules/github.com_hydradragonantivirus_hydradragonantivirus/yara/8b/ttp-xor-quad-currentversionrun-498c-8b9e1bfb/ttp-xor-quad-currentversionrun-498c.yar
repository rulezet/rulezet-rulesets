rule TTP_XOR_QUAD_CurrentVersionRun_498c {
  strings:
    $key_498c = { 1a e3 [2] 3e ed [2] 15 c1 [2] 3b e3 [2] 2f f8 [2] 20 e2 [2] 3e ff [2] 3c fe [2] 27 f8 [2] 3b ff [2] 27 d0 }

  condition:
    any of them
}