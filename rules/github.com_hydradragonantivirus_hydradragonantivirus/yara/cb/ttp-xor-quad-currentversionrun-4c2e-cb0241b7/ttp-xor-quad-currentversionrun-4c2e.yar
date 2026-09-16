rule TTP_XOR_QUAD_CurrentVersionRun_4c2e {
  strings:
    $key_4c2e = { 1f 41 [2] 3b 4f [2] 10 63 [2] 3e 41 [2] 2a 5a [2] 25 40 [2] 3b 5d [2] 39 5c [2] 22 5a [2] 3e 5d [2] 22 72 }

  condition:
    any of them
}