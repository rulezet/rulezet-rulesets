rule TTP_XOR_QUAD_CurrentVersionRun_3c2e {
  strings:
    $key_3c2e = { 6f 41 [2] 4b 4f [2] 60 63 [2] 4e 41 [2] 5a 5a [2] 55 40 [2] 4b 5d [2] 49 5c [2] 52 5a [2] 4e 5d [2] 52 72 }

  condition:
    any of them
}