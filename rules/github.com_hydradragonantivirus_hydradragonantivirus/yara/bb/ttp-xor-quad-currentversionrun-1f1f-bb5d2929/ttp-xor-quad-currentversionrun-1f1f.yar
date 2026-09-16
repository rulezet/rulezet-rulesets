rule TTP_XOR_QUAD_CurrentVersionRun_1f1f {
  strings:
    $key_1f1f = { 4c 70 [2] 68 7e [2] 43 52 [2] 6d 70 [2] 79 6b [2] 76 71 [2] 68 6c [2] 6a 6d [2] 71 6b [2] 6d 6c [2] 71 43 }

  condition:
    any of them
}