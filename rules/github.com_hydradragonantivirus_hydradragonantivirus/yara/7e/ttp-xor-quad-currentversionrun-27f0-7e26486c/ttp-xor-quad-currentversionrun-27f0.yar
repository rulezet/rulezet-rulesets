rule TTP_XOR_QUAD_CurrentVersionRun_27f0 {
  strings:
    $key_27f0 = { 74 9f [2] 50 91 [2] 7b bd [2] 55 9f [2] 41 84 [2] 4e 9e [2] 50 83 [2] 52 82 [2] 49 84 [2] 55 83 [2] 49 ac }

  condition:
    any of them
}