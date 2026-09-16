rule TTP_XOR_QUAD_CurrentVersionRun_043f {
  strings:
    $key_043f = { 57 50 [2] 73 5e [2] 58 72 [2] 76 50 [2] 62 4b [2] 6d 51 [2] 73 4c [2] 71 4d [2] 6a 4b [2] 76 4c [2] 6a 63 }

  condition:
    any of them
}