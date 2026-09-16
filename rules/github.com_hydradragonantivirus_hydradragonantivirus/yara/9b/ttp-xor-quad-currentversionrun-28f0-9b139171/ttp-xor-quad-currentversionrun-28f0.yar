rule TTP_XOR_QUAD_CurrentVersionRun_28f0 {
  strings:
    $key_28f0 = { 7b 9f [2] 5f 91 [2] 74 bd [2] 5a 9f [2] 4e 84 [2] 41 9e [2] 5f 83 [2] 5d 82 [2] 46 84 [2] 5a 83 [2] 46 ac }

  condition:
    any of them
}