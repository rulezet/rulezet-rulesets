rule TTP_XOR_QUAD_CurrentVersionRun_2628 {
  strings:
    $key_2628 = { 75 47 [2] 51 49 [2] 7a 65 [2] 54 47 [2] 40 5c [2] 4f 46 [2] 51 5b [2] 53 5a [2] 48 5c [2] 54 5b [2] 48 74 }

  condition:
    any of them
}