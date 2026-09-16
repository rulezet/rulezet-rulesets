rule TTP_XOR_QUAD_CurrentVersionRun_0508 {
  strings:
    $key_0508 = { 56 67 [2] 72 69 [2] 59 45 [2] 77 67 [2] 63 7c [2] 6c 66 [2] 72 7b [2] 70 7a [2] 6b 7c [2] 77 7b [2] 6b 54 }

  condition:
    any of them
}