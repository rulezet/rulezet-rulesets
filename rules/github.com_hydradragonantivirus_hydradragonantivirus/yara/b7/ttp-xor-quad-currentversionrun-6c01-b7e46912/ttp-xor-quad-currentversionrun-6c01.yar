rule TTP_XOR_QUAD_CurrentVersionRun_6c01 {
  strings:
    $key_6c01 = { 3f 6e [2] 1b 60 [2] 30 4c [2] 1e 6e [2] 0a 75 [2] 05 6f [2] 1b 72 [2] 19 73 [2] 02 75 [2] 1e 72 [2] 02 5d }

  condition:
    any of them
}