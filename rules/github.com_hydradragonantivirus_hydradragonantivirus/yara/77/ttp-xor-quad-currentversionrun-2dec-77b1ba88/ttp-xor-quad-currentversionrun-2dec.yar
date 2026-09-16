rule TTP_XOR_QUAD_CurrentVersionRun_2dec {
  strings:
    $key_2dec = { 7e 83 [2] 5a 8d [2] 71 a1 [2] 5f 83 [2] 4b 98 [2] 44 82 [2] 5a 9f [2] 58 9e [2] 43 98 [2] 5f 9f [2] 43 b0 }

  condition:
    any of them
}