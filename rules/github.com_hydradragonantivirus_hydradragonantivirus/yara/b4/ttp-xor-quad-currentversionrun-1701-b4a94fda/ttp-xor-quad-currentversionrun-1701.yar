rule TTP_XOR_QUAD_CurrentVersionRun_1701 {
  strings:
    $key_1701 = { 44 6e [2] 60 60 [2] 4b 4c [2] 65 6e [2] 71 75 [2] 7e 6f [2] 60 72 [2] 62 73 [2] 79 75 [2] 65 72 [2] 79 5d }

  condition:
    any of them
}