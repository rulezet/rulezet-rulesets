rule TTP_XOR_QUAD_CurrentVersionRun_748a {
  strings:
    $key_748a = { 27 e5 [2] 03 eb [2] 28 c7 [2] 06 e5 [2] 12 fe [2] 1d e4 [2] 03 f9 [2] 01 f8 [2] 1a fe [2] 06 f9 [2] 1a d6 }

  condition:
    any of them
}