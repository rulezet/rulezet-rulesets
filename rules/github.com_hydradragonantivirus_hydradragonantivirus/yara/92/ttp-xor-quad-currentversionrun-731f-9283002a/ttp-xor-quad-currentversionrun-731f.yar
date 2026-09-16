rule TTP_XOR_QUAD_CurrentVersionRun_731f {
  strings:
    $key_731f = { 20 70 [2] 04 7e [2] 2f 52 [2] 01 70 [2] 15 6b [2] 1a 71 [2] 04 6c [2] 06 6d [2] 1d 6b [2] 01 6c [2] 1d 43 }

  condition:
    any of them
}