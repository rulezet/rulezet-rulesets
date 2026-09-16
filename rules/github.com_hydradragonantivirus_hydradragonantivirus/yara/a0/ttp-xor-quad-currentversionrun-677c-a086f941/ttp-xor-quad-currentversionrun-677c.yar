rule TTP_XOR_QUAD_CurrentVersionRun_677c {
  strings:
    $key_677c = { 34 13 [2] 10 1d [2] 3b 31 [2] 15 13 [2] 01 08 [2] 0e 12 [2] 10 0f [2] 12 0e [2] 09 08 [2] 15 0f [2] 09 20 }

  condition:
    any of them
}