rule TTP_XOR_QUAD_CurrentVersionRun_46f0 {
  strings:
    $key_46f0 = { 15 9f [2] 31 91 [2] 1a bd [2] 34 9f [2] 20 84 [2] 2f 9e [2] 31 83 [2] 33 82 [2] 28 84 [2] 34 83 [2] 28 ac }

  condition:
    any of them
}