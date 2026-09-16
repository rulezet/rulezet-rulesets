rule TTP_XOR_QUAD_CurrentVersionRun_12ec {
  strings:
    $key_12ec = { 41 83 [2] 65 8d [2] 4e a1 [2] 60 83 [2] 74 98 [2] 7b 82 [2] 65 9f [2] 67 9e [2] 7c 98 [2] 60 9f [2] 7c b0 }

  condition:
    any of them
}