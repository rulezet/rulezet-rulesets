rule TTP_XOR_QUAD_CurrentVersionRun_31f0 {
  strings:
    $key_31f0 = { 62 9f [2] 46 91 [2] 6d bd [2] 43 9f [2] 57 84 [2] 58 9e [2] 46 83 [2] 44 82 [2] 5f 84 [2] 43 83 [2] 5f ac }

  condition:
    any of them
}