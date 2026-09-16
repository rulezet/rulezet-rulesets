rule TTP_XOR_QUAD_CurrentVersionRun_2028 {
  strings:
    $key_2028 = { 73 47 [2] 57 49 [2] 7c 65 [2] 52 47 [2] 46 5c [2] 49 46 [2] 57 5b [2] 55 5a [2] 4e 5c [2] 52 5b [2] 4e 74 }

  condition:
    any of them
}