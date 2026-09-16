rule TTP_XOR_QUAD_CurrentVersionRun_1733 {
  strings:
    $key_1733 = { 44 5c [2] 60 52 [2] 4b 7e [2] 65 5c [2] 71 47 [2] 7e 5d [2] 60 40 [2] 62 41 [2] 79 47 [2] 65 40 [2] 79 6f }

  condition:
    any of them
}