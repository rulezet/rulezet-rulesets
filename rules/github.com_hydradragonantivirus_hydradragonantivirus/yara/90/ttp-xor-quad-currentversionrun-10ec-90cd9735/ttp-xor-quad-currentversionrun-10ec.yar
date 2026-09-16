rule TTP_XOR_QUAD_CurrentVersionRun_10ec {
  strings:
    $key_10ec = { 43 83 [2] 67 8d [2] 4c a1 [2] 62 83 [2] 76 98 [2] 79 82 [2] 67 9f [2] 65 9e [2] 7e 98 [2] 62 9f [2] 7e b0 }

  condition:
    any of them
}