rule TTP_XOR_QUAD_CurrentVersionRun_0601 {
  strings:
    $key_0601 = { 55 6e [2] 71 60 [2] 5a 4c [2] 74 6e [2] 60 75 [2] 6f 6f [2] 71 72 [2] 73 73 [2] 68 75 [2] 74 72 [2] 68 5d }

  condition:
    any of them
}