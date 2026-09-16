rule TTP_XOR_QUAD_CurrentVersionRun_58f0 {
  strings:
    $key_58f0 = { 0b 9f [2] 2f 91 [2] 04 bd [2] 2a 9f [2] 3e 84 [2] 31 9e [2] 2f 83 [2] 2d 82 [2] 36 84 [2] 2a 83 [2] 36 ac }

  condition:
    any of them
}