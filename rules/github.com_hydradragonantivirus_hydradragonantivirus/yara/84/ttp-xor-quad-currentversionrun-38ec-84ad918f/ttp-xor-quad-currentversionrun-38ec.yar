rule TTP_XOR_QUAD_CurrentVersionRun_38ec {
  strings:
    $key_38ec = { 6b 83 [2] 4f 8d [2] 64 a1 [2] 4a 83 [2] 5e 98 [2] 51 82 [2] 4f 9f [2] 4d 9e [2] 56 98 [2] 4a 9f [2] 56 b0 }

  condition:
    any of them
}