rule TTP_XOR_QUAD_CurrentVersionRun_3528 {
  strings:
    $key_3528 = { 66 47 [2] 42 49 [2] 69 65 [2] 47 47 [2] 53 5c [2] 5c 46 [2] 42 5b [2] 40 5a [2] 5b 5c [2] 47 5b [2] 5b 74 }

  condition:
    any of them
}