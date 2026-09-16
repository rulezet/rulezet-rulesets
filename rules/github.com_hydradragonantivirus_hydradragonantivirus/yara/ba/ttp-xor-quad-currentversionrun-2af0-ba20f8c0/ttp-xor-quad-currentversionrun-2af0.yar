rule TTP_XOR_QUAD_CurrentVersionRun_2af0 {
  strings:
    $key_2af0 = { 79 9f [2] 5d 91 [2] 76 bd [2] 58 9f [2] 4c 84 [2] 43 9e [2] 5d 83 [2] 5f 82 [2] 44 84 [2] 58 83 [2] 44 ac }

  condition:
    any of them
}