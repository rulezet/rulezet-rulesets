rule TTP_XOR_QUAD_CurrentVersionRun_79f0 {
  strings:
    $key_79f0 = { 2a 9f [2] 0e 91 [2] 25 bd [2] 0b 9f [2] 1f 84 [2] 10 9e [2] 0e 83 [2] 0c 82 [2] 17 84 [2] 0b 83 [2] 17 ac }

  condition:
    any of them
}