rule TTP_XOR_QUAD_CurrentVersionRun_06ec {
  strings:
    $key_06ec = { 55 83 [2] 71 8d [2] 5a a1 [2] 74 83 [2] 60 98 [2] 6f 82 [2] 71 9f [2] 73 9e [2] 68 98 [2] 74 9f [2] 68 b0 }

  condition:
    any of them
}