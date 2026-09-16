rule TTP_XOR_QUAD_CurrentVersionRun_567f {
  strings:
    $key_567f = { 05 10 [2] 21 1e [2] 0a 32 [2] 24 10 [2] 30 0b [2] 3f 11 [2] 21 0c [2] 23 0d [2] 38 0b [2] 24 0c [2] 38 23 }

  condition:
    any of them
}