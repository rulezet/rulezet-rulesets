rule TTP_XOR_QUAD_CurrentVersionRun_4cf0 {
  strings:
    $key_4cf0 = { 1f 9f [2] 3b 91 [2] 10 bd [2] 3e 9f [2] 2a 84 [2] 25 9e [2] 3b 83 [2] 39 82 [2] 22 84 [2] 3e 83 [2] 22 ac }

  condition:
    any of them
}