rule TTP_XOR_QUAD_CurrentVersionRun_08f0 {
  strings:
    $key_08f0 = { 5b 9f [2] 7f 91 [2] 54 bd [2] 7a 9f [2] 6e 84 [2] 61 9e [2] 7f 83 [2] 7d 82 [2] 66 84 [2] 7a 83 [2] 66 ac }

  condition:
    any of them
}