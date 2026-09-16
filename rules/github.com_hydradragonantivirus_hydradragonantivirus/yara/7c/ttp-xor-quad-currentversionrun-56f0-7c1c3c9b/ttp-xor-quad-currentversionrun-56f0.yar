rule TTP_XOR_QUAD_CurrentVersionRun_56f0 {
  strings:
    $key_56f0 = { 05 9f [2] 21 91 [2] 0a bd [2] 24 9f [2] 30 84 [2] 3f 9e [2] 21 83 [2] 23 82 [2] 38 84 [2] 24 83 [2] 38 ac }

  condition:
    any of them
}