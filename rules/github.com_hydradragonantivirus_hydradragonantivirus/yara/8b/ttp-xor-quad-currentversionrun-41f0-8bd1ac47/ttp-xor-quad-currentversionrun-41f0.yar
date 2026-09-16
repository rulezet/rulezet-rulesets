rule TTP_XOR_QUAD_CurrentVersionRun_41f0 {
  strings:
    $key_41f0 = { 12 9f [2] 36 91 [2] 1d bd [2] 33 9f [2] 27 84 [2] 28 9e [2] 36 83 [2] 34 82 [2] 2f 84 [2] 33 83 [2] 2f ac }

  condition:
    any of them
}