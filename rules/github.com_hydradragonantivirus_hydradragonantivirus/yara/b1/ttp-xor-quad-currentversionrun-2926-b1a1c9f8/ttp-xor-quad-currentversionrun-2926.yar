rule TTP_XOR_QUAD_CurrentVersionRun_2926 {
  strings:
    $key_2926 = { 7a 49 [2] 5e 47 [2] 75 6b [2] 5b 49 [2] 4f 52 [2] 40 48 [2] 5e 55 [2] 5c 54 [2] 47 52 [2] 5b 55 [2] 47 7a }

  condition:
    any of them
}