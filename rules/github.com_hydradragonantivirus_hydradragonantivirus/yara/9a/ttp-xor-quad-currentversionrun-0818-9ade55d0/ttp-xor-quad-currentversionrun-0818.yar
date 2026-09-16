rule TTP_XOR_QUAD_CurrentVersionRun_0818 {
  strings:
    $key_0818 = { 5b 77 [2] 7f 79 [2] 54 55 [2] 7a 77 [2] 6e 6c [2] 61 76 [2] 7f 6b [2] 7d 6a [2] 66 6c [2] 7a 6b [2] 66 44 }

  condition:
    any of them
}