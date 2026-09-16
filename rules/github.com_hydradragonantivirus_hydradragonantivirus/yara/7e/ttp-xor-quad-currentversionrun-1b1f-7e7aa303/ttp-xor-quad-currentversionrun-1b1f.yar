rule TTP_XOR_QUAD_CurrentVersionRun_1b1f {
  strings:
    $key_1b1f = { 48 70 [2] 6c 7e [2] 47 52 [2] 69 70 [2] 7d 6b [2] 72 71 [2] 6c 6c [2] 6e 6d [2] 75 6b [2] 69 6c [2] 75 43 }

  condition:
    any of them
}