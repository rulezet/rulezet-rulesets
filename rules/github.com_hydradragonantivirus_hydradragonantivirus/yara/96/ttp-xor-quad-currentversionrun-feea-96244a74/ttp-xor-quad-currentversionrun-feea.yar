rule TTP_XOR_QUAD_CurrentVersionRun_feea {
  strings:
    $key_feea = { ad 85 [2] 89 8b [2] a2 a7 [2] 8c 85 [2] 98 9e [2] 97 84 [2] 89 99 [2] 8b 98 [2] 90 9e [2] 8c 99 [2] 90 b6 }

  condition:
    any of them
}