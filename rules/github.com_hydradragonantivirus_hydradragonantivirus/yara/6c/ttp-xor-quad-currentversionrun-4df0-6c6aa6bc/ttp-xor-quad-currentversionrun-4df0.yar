rule TTP_XOR_QUAD_CurrentVersionRun_4df0 {
  strings:
    $key_4df0 = { 1e 9f [2] 3a 91 [2] 11 bd [2] 3f 9f [2] 2b 84 [2] 24 9e [2] 3a 83 [2] 38 82 [2] 23 84 [2] 3f 83 [2] 23 ac }

  condition:
    any of them
}