rule TTP_XOR_QUAD_CurrentVersionRun_51f0 {
  strings:
    $key_51f0 = { 02 9f [2] 26 91 [2] 0d bd [2] 23 9f [2] 37 84 [2] 38 9e [2] 26 83 [2] 24 82 [2] 3f 84 [2] 23 83 [2] 3f ac }

  condition:
    any of them
}