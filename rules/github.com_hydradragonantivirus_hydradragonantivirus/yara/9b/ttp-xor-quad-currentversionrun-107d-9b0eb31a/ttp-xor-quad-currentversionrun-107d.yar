rule TTP_XOR_QUAD_CurrentVersionRun_107d {
  strings:
    $key_107d = { 43 12 [2] 67 1c [2] 4c 30 [2] 62 12 [2] 76 09 [2] 79 13 [2] 67 0e [2] 65 0f [2] 7e 09 [2] 62 0e [2] 7e 21 }

  condition:
    any of them
}