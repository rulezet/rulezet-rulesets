rule TTP_XOR_QUAD_CurrentVersionRun_6f1f {
  strings:
    $key_6f1f = { 3c 70 [2] 18 7e [2] 33 52 [2] 1d 70 [2] 09 6b [2] 06 71 [2] 18 6c [2] 1a 6d [2] 01 6b [2] 1d 6c [2] 01 43 }

  condition:
    any of them
}