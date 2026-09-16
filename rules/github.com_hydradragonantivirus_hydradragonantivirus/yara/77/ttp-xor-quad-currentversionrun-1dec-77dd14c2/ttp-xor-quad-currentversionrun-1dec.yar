rule TTP_XOR_QUAD_CurrentVersionRun_1dec {
  strings:
    $key_1dec = { 4e 83 [2] 6a 8d [2] 41 a1 [2] 6f 83 [2] 7b 98 [2] 74 82 [2] 6a 9f [2] 68 9e [2] 73 98 [2] 6f 9f [2] 73 b0 }

  condition:
    any of them
}