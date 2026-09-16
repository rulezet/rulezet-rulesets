rule TTP_XOR_QUAD_CurrentVersionRun_32ec {
  strings:
    $key_32ec = { 61 83 [2] 45 8d [2] 6e a1 [2] 40 83 [2] 54 98 [2] 5b 82 [2] 45 9f [2] 47 9e [2] 5c 98 [2] 40 9f [2] 5c b0 }

  condition:
    any of them
}