rule TTP_XOR_QUAD_CurrentVersionRun_7ef0 {
  strings:
    $key_7ef0 = { 2d 9f [2] 09 91 [2] 22 bd [2] 0c 9f [2] 18 84 [2] 17 9e [2] 09 83 [2] 0b 82 [2] 10 84 [2] 0c 83 [2] 10 ac }

  condition:
    any of them
}