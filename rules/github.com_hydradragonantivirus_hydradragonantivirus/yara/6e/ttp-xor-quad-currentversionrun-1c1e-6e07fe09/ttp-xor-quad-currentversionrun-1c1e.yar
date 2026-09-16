rule TTP_XOR_QUAD_CurrentVersionRun_1c1e {
  strings:
    $key_1c1e = { 4f 71 [2] 6b 7f [2] 40 53 [2] 6e 71 [2] 7a 6a [2] 75 70 [2] 6b 6d [2] 69 6c [2] 72 6a [2] 6e 6d [2] 72 42 }

  condition:
    any of them
}