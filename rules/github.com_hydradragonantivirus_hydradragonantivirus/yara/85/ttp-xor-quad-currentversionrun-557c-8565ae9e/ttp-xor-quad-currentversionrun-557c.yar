rule TTP_XOR_QUAD_CurrentVersionRun_557c {
  strings:
    $key_557c = { 06 13 [2] 22 1d [2] 09 31 [2] 27 13 [2] 33 08 [2] 3c 12 [2] 22 0f [2] 20 0e [2] 3b 08 [2] 27 0f [2] 3b 20 }

  condition:
    any of them
}