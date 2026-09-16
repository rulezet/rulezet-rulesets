rule TTP_XOR_QUAD_CurrentVersionRun_0333 {
  strings:
    $key_0333 = { 50 5c [2] 74 52 [2] 5f 7e [2] 71 5c [2] 65 47 [2] 6a 5d [2] 74 40 [2] 76 41 [2] 6d 47 [2] 71 40 [2] 6d 6f }

  condition:
    any of them
}