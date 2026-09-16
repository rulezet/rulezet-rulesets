rule TTP_XOR_QUAD_CurrentVersionRun_2a2f {
  strings:
    $key_2a2f = { 79 40 [2] 5d 4e [2] 76 62 [2] 58 40 [2] 4c 5b [2] 43 41 [2] 5d 5c [2] 5f 5d [2] 44 5b [2] 58 5c [2] 44 73 }

  condition:
    any of them
}