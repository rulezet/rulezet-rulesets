rule TTP_XOR_QUAD_CurrentVersionRun_348c {
  strings:
    $key_348c = { 67 e3 [2] 43 ed [2] 68 c1 [2] 46 e3 [2] 52 f8 [2] 5d e2 [2] 43 ff [2] 41 fe [2] 5a f8 [2] 46 ff [2] 5a d0 }

  condition:
    any of them
}