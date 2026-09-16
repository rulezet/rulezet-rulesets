rule TTP_XOR_QUAD_CurrentVersionRun_2c28 {
  strings:
    $key_2c28 = { 7f 47 [2] 5b 49 [2] 70 65 [2] 5e 47 [2] 4a 5c [2] 45 46 [2] 5b 5b [2] 59 5a [2] 42 5c [2] 5e 5b [2] 42 74 }

  condition:
    any of them
}