rule TTP_XOR_QUAD_CurrentVersionRun_fef1 {
  strings:
    $key_fef1 = { ad 9e [2] 89 90 [2] a2 bc [2] 8c 9e [2] 98 85 [2] 97 9f [2] 89 82 [2] 8b 83 [2] 90 85 [2] 8c 82 [2] 90 ad }

  condition:
    any of them
}