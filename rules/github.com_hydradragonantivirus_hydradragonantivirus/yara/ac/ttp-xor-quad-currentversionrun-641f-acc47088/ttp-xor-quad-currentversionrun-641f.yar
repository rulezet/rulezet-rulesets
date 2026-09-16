rule TTP_XOR_QUAD_CurrentVersionRun_641f {
  strings:
    $key_641f = { 37 70 [2] 13 7e [2] 38 52 [2] 16 70 [2] 02 6b [2] 0d 71 [2] 13 6c [2] 11 6d [2] 0a 6b [2] 16 6c [2] 0a 43 }

  condition:
    any of them
}