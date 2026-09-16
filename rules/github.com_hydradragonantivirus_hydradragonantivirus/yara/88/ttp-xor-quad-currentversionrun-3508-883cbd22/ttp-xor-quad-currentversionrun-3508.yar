rule TTP_XOR_QUAD_CurrentVersionRun_3508 {
  strings:
    $key_3508 = { 66 67 [2] 42 69 [2] 69 45 [2] 47 67 [2] 53 7c [2] 5c 66 [2] 42 7b [2] 40 7a [2] 5b 7c [2] 47 7b [2] 5b 54 }

  condition:
    any of them
}