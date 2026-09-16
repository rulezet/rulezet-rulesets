rule TTP_XOR_QUAD_CurrentVersionRun_791f {
  strings:
    $key_791f = { 2a 70 [2] 0e 7e [2] 25 52 [2] 0b 70 [2] 1f 6b [2] 10 71 [2] 0e 6c [2] 0c 6d [2] 17 6b [2] 0b 6c [2] 17 43 }

  condition:
    any of them
}