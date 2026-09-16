rule TTP_XOR_QUAD_CurrentVersionRun_412f {
  strings:
    $key_412f = { 12 40 [2] 36 4e [2] 1d 62 [2] 33 40 [2] 27 5b [2] 28 41 [2] 36 5c [2] 34 5d [2] 2f 5b [2] 33 5c [2] 2f 73 }

  condition:
    any of them
}