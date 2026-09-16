rule TTP_XOR_QUAD_CurrentVersionRun_e56f {
  strings:
    $key_e56f = { b6 00 [2] 92 0e [2] b9 22 [2] 97 00 [2] 83 1b [2] 8c 01 [2] 92 1c [2] 90 1d [2] 8b 1b [2] 97 1c [2] 8b 33 }

  condition:
    any of them
}