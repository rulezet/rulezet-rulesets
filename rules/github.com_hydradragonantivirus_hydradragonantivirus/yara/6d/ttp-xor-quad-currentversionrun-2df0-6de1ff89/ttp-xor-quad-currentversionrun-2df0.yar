rule TTP_XOR_QUAD_CurrentVersionRun_2df0 {
  strings:
    $key_2df0 = { 7e 9f [2] 5a 91 [2] 71 bd [2] 5f 9f [2] 4b 84 [2] 44 9e [2] 5a 83 [2] 58 82 [2] 43 84 [2] 5f 83 [2] 43 ac }

  condition:
    any of them
}