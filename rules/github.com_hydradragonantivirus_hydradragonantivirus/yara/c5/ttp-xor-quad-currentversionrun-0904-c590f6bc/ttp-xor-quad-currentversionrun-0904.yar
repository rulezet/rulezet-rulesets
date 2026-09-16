rule TTP_XOR_QUAD_CurrentVersionRun_0904 {
  strings:
    $key_0904 = { 5a 6b [2] 7e 65 [2] 55 49 [2] 7b 6b [2] 6f 70 [2] 60 6a [2] 7e 77 [2] 7c 76 [2] 67 70 [2] 7b 77 [2] 67 58 }

  condition:
    any of them
}