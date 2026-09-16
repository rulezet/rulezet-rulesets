rule TTP_XOR_QUAD_CurrentVersionRun_7cf0 {
  strings:
    $key_7cf0 = { 2f 9f [2] 0b 91 [2] 20 bd [2] 0e 9f [2] 1a 84 [2] 15 9e [2] 0b 83 [2] 09 82 [2] 12 84 [2] 0e 83 [2] 12 ac }

  condition:
    any of them
}