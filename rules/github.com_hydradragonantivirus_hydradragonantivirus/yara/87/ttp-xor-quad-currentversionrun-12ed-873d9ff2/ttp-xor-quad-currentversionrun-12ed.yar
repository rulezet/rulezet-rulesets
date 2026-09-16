rule TTP_XOR_QUAD_CurrentVersionRun_12ed {
  strings:
    $key_12ed = { 41 82 [2] 65 8c [2] 4e a0 [2] 60 82 [2] 74 99 [2] 7b 83 [2] 65 9e [2] 67 9f [2] 7c 99 [2] 60 9e [2] 7c b1 }

  condition:
    any of them
}