rule TTP_XOR_QUAD_CurrentVersionRun_0d1e {
  strings:
    $key_0d1e = { 5e 71 [2] 7a 7f [2] 51 53 [2] 7f 71 [2] 6b 6a [2] 64 70 [2] 7a 6d [2] 78 6c [2] 63 6a [2] 7f 6d [2] 63 42 }

  condition:
    any of them
}