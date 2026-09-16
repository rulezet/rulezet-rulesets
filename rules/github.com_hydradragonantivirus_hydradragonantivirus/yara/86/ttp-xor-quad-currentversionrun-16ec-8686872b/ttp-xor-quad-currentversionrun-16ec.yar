rule TTP_XOR_QUAD_CurrentVersionRun_16ec {
  strings:
    $key_16ec = { 45 83 [2] 61 8d [2] 4a a1 [2] 64 83 [2] 70 98 [2] 7f 82 [2] 61 9f [2] 63 9e [2] 78 98 [2] 64 9f [2] 78 b0 }

  condition:
    any of them
}