rule TTP_XOR_QUAD_CurrentVersionRun_ecf0 {
  strings:
    $key_ecf0 = { bf 9f [2] 9b 91 [2] b0 bd [2] 9e 9f [2] 8a 84 [2] 85 9e [2] 9b 83 [2] 99 82 [2] 82 84 [2] 9e 83 [2] 82 ac }

  condition:
    any of them
}