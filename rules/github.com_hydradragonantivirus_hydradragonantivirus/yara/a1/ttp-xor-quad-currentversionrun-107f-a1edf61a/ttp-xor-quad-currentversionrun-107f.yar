rule TTP_XOR_QUAD_CurrentVersionRun_107f {
  strings:
    $key_107f = { 43 10 [2] 67 1e [2] 4c 32 [2] 62 10 [2] 76 0b [2] 79 11 [2] 67 0c [2] 65 0d [2] 7e 0b [2] 62 0c [2] 7e 23 }

  condition:
    any of them
}