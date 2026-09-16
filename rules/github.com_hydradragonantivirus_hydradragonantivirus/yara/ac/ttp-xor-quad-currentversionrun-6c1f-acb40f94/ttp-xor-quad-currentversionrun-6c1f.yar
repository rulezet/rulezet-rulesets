rule TTP_XOR_QUAD_CurrentVersionRun_6c1f {
  strings:
    $key_6c1f = { 3f 70 [2] 1b 7e [2] 30 52 [2] 1e 70 [2] 0a 6b [2] 05 71 [2] 1b 6c [2] 19 6d [2] 02 6b [2] 1e 6c [2] 02 43 }

  condition:
    any of them
}