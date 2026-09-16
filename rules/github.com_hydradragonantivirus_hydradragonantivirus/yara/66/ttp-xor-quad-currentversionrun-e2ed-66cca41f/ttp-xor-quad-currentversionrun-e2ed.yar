rule TTP_XOR_QUAD_CurrentVersionRun_e2ed {
  strings:
    $key_e2ed = { b1 82 [2] 95 8c [2] be a0 [2] 90 82 [2] 84 99 [2] 8b 83 [2] 95 9e [2] 97 9f [2] 8c 99 [2] 90 9e [2] 8c b1 }

  condition:
    any of them
}