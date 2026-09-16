rule TTP_XOR_QUAD_CurrentVersionRun_62ec {
  strings:
    $key_62ec = { 31 83 [2] 15 8d [2] 3e a1 [2] 10 83 [2] 04 98 [2] 0b 82 [2] 15 9f [2] 17 9e [2] 0c 98 [2] 10 9f [2] 0c b0 }

  condition:
    any of them
}