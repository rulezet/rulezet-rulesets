rule TTP_XOR_QUAD_CurrentVersionRun_511f {
  strings:
    $key_511f = { 02 70 [2] 26 7e [2] 0d 52 [2] 23 70 [2] 37 6b [2] 38 71 [2] 26 6c [2] 24 6d [2] 3f 6b [2] 23 6c [2] 3f 43 }

  condition:
    any of them
}