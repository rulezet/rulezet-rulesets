rule TTP_XOR_QUAD_CurrentVersionRun_6b2e {
  strings:
    $key_6b2e = { 38 41 [2] 1c 4f [2] 37 63 [2] 19 41 [2] 0d 5a [2] 02 40 [2] 1c 5d [2] 1e 5c [2] 05 5a [2] 19 5d [2] 05 72 }

  condition:
    any of them
}