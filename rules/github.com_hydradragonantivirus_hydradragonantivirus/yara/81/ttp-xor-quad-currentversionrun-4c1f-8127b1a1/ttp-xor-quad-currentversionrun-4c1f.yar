rule TTP_XOR_QUAD_CurrentVersionRun_4c1f {
  strings:
    $key_4c1f = { 1f 70 [2] 3b 7e [2] 10 52 [2] 3e 70 [2] 2a 6b [2] 25 71 [2] 3b 6c [2] 39 6d [2] 22 6b [2] 3e 6c [2] 22 43 }

  condition:
    any of them
}