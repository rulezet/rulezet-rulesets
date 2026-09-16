rule TTP_XOR_QUAD_CurrentVersionRun_5dec {
  strings:
    $key_5dec = { 0e 83 [2] 2a 8d [2] 01 a1 [2] 2f 83 [2] 3b 98 [2] 34 82 [2] 2a 9f [2] 28 9e [2] 33 98 [2] 2f 9f [2] 33 b0 }

  condition:
    any of them
}