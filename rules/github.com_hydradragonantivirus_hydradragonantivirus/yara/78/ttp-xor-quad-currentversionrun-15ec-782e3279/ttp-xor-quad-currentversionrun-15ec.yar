rule TTP_XOR_QUAD_CurrentVersionRun_15ec {
  strings:
    $key_15ec = { 46 83 [2] 62 8d [2] 49 a1 [2] 67 83 [2] 73 98 [2] 7c 82 [2] 62 9f [2] 60 9e [2] 7b 98 [2] 67 9f [2] 7b b0 }

  condition:
    any of them
}