rule TTP_XOR_QUAD_CurrentVersionRun_348a {
  strings:
    $key_348a = { 67 e5 [2] 43 eb [2] 68 c7 [2] 46 e5 [2] 52 fe [2] 5d e4 [2] 43 f9 [2] 41 f8 [2] 5a fe [2] 46 f9 [2] 5a d6 }

  condition:
    any of them
}