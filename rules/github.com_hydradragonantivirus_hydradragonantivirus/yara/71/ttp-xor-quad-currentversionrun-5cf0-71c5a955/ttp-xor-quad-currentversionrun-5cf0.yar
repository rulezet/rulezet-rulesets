rule TTP_XOR_QUAD_CurrentVersionRun_5cf0 {
  strings:
    $key_5cf0 = { 0f 9f [2] 2b 91 [2] 00 bd [2] 2e 9f [2] 3a 84 [2] 35 9e [2] 2b 83 [2] 29 82 [2] 32 84 [2] 2e 83 [2] 32 ac }

  condition:
    any of them
}