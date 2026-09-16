rule TTP_XOR_QUAD_CurrentVersionRun_126f {
  strings:
    $key_126f = { 41 00 [2] 65 0e [2] 4e 22 [2] 60 00 [2] 74 1b [2] 7b 01 [2] 65 1c [2] 67 1d [2] 7c 1b [2] 60 1c [2] 7c 33 }

  condition:
    any of them
}