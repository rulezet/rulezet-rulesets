rule TTP_XOR_QUAD_CurrentVersionRun_5601 {
  strings:
    $key_5601 = { 05 6e [2] 21 60 [2] 0a 4c [2] 24 6e [2] 30 75 [2] 3f 6f [2] 21 72 [2] 23 73 [2] 38 75 [2] 24 72 [2] 38 5d }

  condition:
    any of them
}