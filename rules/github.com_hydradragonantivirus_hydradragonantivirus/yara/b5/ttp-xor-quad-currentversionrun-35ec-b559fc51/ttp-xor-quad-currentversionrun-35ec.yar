rule TTP_XOR_QUAD_CurrentVersionRun_35ec {
  strings:
    $key_35ec = { 66 83 [2] 42 8d [2] 69 a1 [2] 47 83 [2] 53 98 [2] 5c 82 [2] 42 9f [2] 40 9e [2] 5b 98 [2] 47 9f [2] 5b b0 }

  condition:
    any of them
}