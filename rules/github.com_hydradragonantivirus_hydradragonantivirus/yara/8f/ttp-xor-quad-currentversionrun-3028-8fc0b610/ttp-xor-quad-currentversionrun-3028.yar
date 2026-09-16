rule TTP_XOR_QUAD_CurrentVersionRun_3028 {
  strings:
    $key_3028 = { 63 47 [2] 47 49 [2] 6c 65 [2] 42 47 [2] 56 5c [2] 59 46 [2] 47 5b [2] 45 5a [2] 5e 5c [2] 42 5b [2] 5e 74 }

  condition:
    any of them
}