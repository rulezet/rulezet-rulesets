rule TTP_XOR_QUAD_CurrentVersionRun_6cf0 {
  strings:
    $key_6cf0 = { 3f 9f [2] 1b 91 [2] 30 bd [2] 1e 9f [2] 0a 84 [2] 05 9e [2] 1b 83 [2] 19 82 [2] 02 84 [2] 1e 83 [2] 02 ac }

  condition:
    any of them
}