rule TTP_XOR_QUAD_CurrentVersionRun_3008 {
  strings:
    $key_3008 = { 63 67 [2] 47 69 [2] 6c 45 [2] 42 67 [2] 56 7c [2] 59 66 [2] 47 7b [2] 45 7a [2] 5e 7c [2] 42 7b [2] 5e 54 }

  condition:
    any of them
}