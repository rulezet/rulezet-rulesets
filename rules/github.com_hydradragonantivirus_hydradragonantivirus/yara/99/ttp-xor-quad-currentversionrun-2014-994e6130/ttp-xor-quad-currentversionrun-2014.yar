rule TTP_XOR_QUAD_CurrentVersionRun_2014 {
  strings:
    $key_2014 = { 73 7b [2] 57 75 [2] 7c 59 [2] 52 7b [2] 46 60 [2] 49 7a [2] 57 67 [2] 55 66 [2] 4e 60 [2] 52 67 [2] 4e 48 }

  condition:
    any of them
}