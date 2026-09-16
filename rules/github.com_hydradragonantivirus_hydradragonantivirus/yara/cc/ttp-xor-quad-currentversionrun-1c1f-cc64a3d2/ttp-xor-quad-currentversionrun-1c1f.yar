rule TTP_XOR_QUAD_CurrentVersionRun_1c1f {
  strings:
    $key_1c1f = { 4f 70 [2] 6b 7e [2] 40 52 [2] 6e 70 [2] 7a 6b [2] 75 71 [2] 6b 6c [2] 69 6d [2] 72 6b [2] 6e 6c [2] 72 43 }

  condition:
    any of them
}