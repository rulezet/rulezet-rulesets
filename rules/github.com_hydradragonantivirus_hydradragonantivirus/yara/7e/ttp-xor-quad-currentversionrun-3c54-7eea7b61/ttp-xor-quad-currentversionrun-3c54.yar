rule TTP_XOR_QUAD_CurrentVersionRun_3c54 {
  strings:
    $key_3c54 = { 6f 3b [2] 4b 35 [2] 60 19 [2] 4e 3b [2] 5a 20 [2] 55 3a [2] 4b 27 [2] 49 26 [2] 52 20 [2] 4e 27 [2] 52 08 }

  condition:
    any of them
}