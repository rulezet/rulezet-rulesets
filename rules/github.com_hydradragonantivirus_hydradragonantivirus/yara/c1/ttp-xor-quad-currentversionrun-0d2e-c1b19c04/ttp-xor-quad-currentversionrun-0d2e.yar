rule TTP_XOR_QUAD_CurrentVersionRun_0d2e {
  strings:
    $key_0d2e = { 5e 41 [2] 7a 4f [2] 51 63 [2] 7f 41 [2] 6b 5a [2] 64 40 [2] 7a 5d [2] 78 5c [2] 63 5a [2] 7f 5d [2] 63 72 }

  condition:
    any of them
}