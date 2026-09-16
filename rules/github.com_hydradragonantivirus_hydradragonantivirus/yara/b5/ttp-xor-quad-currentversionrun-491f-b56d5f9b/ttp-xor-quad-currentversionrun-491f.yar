rule TTP_XOR_QUAD_CurrentVersionRun_491f {
  strings:
    $key_491f = { 1a 70 [2] 3e 7e [2] 15 52 [2] 3b 70 [2] 2f 6b [2] 20 71 [2] 3e 6c [2] 3c 6d [2] 27 6b [2] 3b 6c [2] 27 43 }

  condition:
    any of them
}