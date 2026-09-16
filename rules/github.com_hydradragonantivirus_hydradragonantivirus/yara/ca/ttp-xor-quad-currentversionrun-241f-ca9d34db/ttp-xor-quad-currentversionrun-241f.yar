rule TTP_XOR_QUAD_CurrentVersionRun_241f {
  strings:
    $key_241f = { 77 70 [2] 53 7e [2] 78 52 [2] 56 70 [2] 42 6b [2] 4d 71 [2] 53 6c [2] 51 6d [2] 4a 6b [2] 56 6c [2] 4a 43 }

  condition:
    any of them
}