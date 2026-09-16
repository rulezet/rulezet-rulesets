rule TTP_XOR_QUAD_CurrentVersionRun_177c {
  strings:
    $key_177c = { 44 13 [2] 60 1d [2] 4b 31 [2] 65 13 [2] 71 08 [2] 7e 12 [2] 60 0f [2] 62 0e [2] 79 08 [2] 65 0f [2] 79 20 }

  condition:
    any of them
}