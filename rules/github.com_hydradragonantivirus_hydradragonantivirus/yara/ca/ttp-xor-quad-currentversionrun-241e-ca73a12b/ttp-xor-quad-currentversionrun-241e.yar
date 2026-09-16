rule TTP_XOR_QUAD_CurrentVersionRun_241e {
  strings:
    $key_241e = { 77 71 [2] 53 7f [2] 78 53 [2] 56 71 [2] 42 6a [2] 4d 70 [2] 53 6d [2] 51 6c [2] 4a 6a [2] 56 6d [2] 4a 42 }

  condition:
    any of them
}