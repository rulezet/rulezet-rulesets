rule TTP_XOR_QUAD_CurrentVersionRun_39f0 {
  strings:
    $key_39f0 = { 6a 9f [2] 4e 91 [2] 65 bd [2] 4b 9f [2] 5f 84 [2] 50 9e [2] 4e 83 [2] 4c 82 [2] 57 84 [2] 4b 83 [2] 57 ac }

  condition:
    any of them
}