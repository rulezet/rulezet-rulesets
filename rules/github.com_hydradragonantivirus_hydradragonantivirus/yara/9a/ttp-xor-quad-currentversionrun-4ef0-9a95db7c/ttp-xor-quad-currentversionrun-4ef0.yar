rule TTP_XOR_QUAD_CurrentVersionRun_4ef0 {
  strings:
    $key_4ef0 = { 1d 9f [2] 39 91 [2] 12 bd [2] 3c 9f [2] 28 84 [2] 27 9e [2] 39 83 [2] 3b 82 [2] 20 84 [2] 3c 83 [2] 20 ac }

  condition:
    any of them
}