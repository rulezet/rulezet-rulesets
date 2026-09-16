rule TTP_XOR_QUAD_CurrentVersionRun_feec {
  strings:
    $key_feec = { ad 83 [2] 89 8d [2] a2 a1 [2] 8c 83 [2] 98 98 [2] 97 82 [2] 89 9f [2] 8b 9e [2] 90 98 [2] 8c 9f [2] 90 b0 }

  condition:
    any of them
}