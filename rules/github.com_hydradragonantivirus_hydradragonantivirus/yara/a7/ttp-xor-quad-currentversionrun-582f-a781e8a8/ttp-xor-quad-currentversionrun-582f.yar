rule TTP_XOR_QUAD_CurrentVersionRun_582f {
  strings:
    $key_582f = { 0b 40 [2] 2f 4e [2] 04 62 [2] 2a 40 [2] 3e 5b [2] 31 41 [2] 2f 5c [2] 2d 5d [2] 36 5b [2] 2a 5c [2] 36 73 }

  condition:
    any of them
}