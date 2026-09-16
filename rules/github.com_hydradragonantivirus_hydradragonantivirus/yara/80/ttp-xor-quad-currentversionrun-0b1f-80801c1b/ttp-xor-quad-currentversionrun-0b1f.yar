rule TTP_XOR_QUAD_CurrentVersionRun_0b1f {
  strings:
    $key_0b1f = { 58 70 [2] 7c 7e [2] 57 52 [2] 79 70 [2] 6d 6b [2] 62 71 [2] 7c 6c [2] 7e 6d [2] 65 6b [2] 79 6c [2] 65 43 }

  condition:
    any of them
}