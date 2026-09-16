rule TTP_XOR_QUAD_CurrentVersionRun_2826 {
  strings:
    $key_2826 = { 7b 49 [2] 5f 47 [2] 74 6b [2] 5a 49 [2] 4e 52 [2] 41 48 [2] 5f 55 [2] 5d 54 [2] 46 52 [2] 5a 55 [2] 46 7a }

  condition:
    any of them
}