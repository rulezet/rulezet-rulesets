rule TTP_XOR_QUAD_CurrentVersionRun_512f {
  strings:
    $key_512f = { 02 40 [2] 26 4e [2] 0d 62 [2] 23 40 [2] 37 5b [2] 38 41 [2] 26 5c [2] 24 5d [2] 3f 5b [2] 23 5c [2] 3f 73 }

  condition:
    any of them
}