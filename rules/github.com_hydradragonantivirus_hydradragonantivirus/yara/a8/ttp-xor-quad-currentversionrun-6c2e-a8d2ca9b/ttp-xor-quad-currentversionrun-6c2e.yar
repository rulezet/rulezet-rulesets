rule TTP_XOR_QUAD_CurrentVersionRun_6c2e {
  strings:
    $key_6c2e = { 3f 41 [2] 1b 4f [2] 30 63 [2] 1e 41 [2] 0a 5a [2] 05 40 [2] 1b 5d [2] 19 5c [2] 02 5a [2] 1e 5d [2] 02 72 }

  condition:
    any of them
}