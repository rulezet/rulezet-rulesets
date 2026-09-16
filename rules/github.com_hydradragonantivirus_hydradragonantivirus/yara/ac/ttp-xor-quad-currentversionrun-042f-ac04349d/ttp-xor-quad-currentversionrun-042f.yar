rule TTP_XOR_QUAD_CurrentVersionRun_042f {
  strings:
    $key_042f = { 57 40 [2] 73 4e [2] 58 62 [2] 76 40 [2] 62 5b [2] 6d 41 [2] 73 5c [2] 71 5d [2] 6a 5b [2] 76 5c [2] 6a 73 }

  condition:
    any of them
}