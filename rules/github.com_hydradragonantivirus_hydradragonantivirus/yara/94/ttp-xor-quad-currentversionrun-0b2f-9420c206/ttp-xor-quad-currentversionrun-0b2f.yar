rule TTP_XOR_QUAD_CurrentVersionRun_0b2f {
  strings:
    $key_0b2f = { 58 40 [2] 7c 4e [2] 57 62 [2] 79 40 [2] 6d 5b [2] 62 41 [2] 7c 5c [2] 7e 5d [2] 65 5b [2] 79 5c [2] 65 73 }

  condition:
    any of them
}