rule TTP_XOR_QUAD_CurrentVersionRun_721e {
  strings:
    $key_721e = { 21 71 [2] 05 7f [2] 2e 53 [2] 00 71 [2] 14 6a [2] 1b 70 [2] 05 6d [2] 07 6c [2] 1c 6a [2] 00 6d [2] 1c 42 }

  condition:
    any of them
}