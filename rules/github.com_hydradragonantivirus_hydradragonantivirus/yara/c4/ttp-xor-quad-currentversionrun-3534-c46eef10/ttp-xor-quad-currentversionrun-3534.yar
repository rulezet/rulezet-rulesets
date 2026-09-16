rule TTP_XOR_QUAD_CurrentVersionRun_3534 {
  strings:
    $key_3534 = { 66 5b [2] 42 55 [2] 69 79 [2] 47 5b [2] 53 40 [2] 5c 5a [2] 42 47 [2] 40 46 [2] 5b 40 [2] 47 47 [2] 5b 68 }

  condition:
    any of them
}