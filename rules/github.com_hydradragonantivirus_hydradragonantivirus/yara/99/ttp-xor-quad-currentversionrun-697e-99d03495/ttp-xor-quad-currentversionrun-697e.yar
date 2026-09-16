rule TTP_XOR_QUAD_CurrentVersionRun_697e {
  strings:
    $key_697e = { 3a 11 [2] 1e 1f [2] 35 33 [2] 1b 11 [2] 0f 0a [2] 00 10 [2] 1e 0d [2] 1c 0c [2] 07 0a [2] 1b 0d [2] 07 22 }

  condition:
    any of them
}