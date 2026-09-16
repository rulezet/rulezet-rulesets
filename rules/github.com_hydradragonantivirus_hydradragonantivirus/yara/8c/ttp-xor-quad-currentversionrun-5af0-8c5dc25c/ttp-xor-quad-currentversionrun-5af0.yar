rule TTP_XOR_QUAD_CurrentVersionRun_5af0 {
  strings:
    $key_5af0 = { 09 9f [2] 2d 91 [2] 06 bd [2] 28 9f [2] 3c 84 [2] 33 9e [2] 2d 83 [2] 2f 82 [2] 34 84 [2] 28 83 [2] 34 ac }

  condition:
    any of them
}