rule TTP_XOR_QUAD_CurrentVersionRun_6218 {
  strings:
    $key_6218 = { 31 77 [2] 15 79 [2] 3e 55 [2] 10 77 [2] 04 6c [2] 0b 76 [2] 15 6b [2] 17 6a [2] 0c 6c [2] 10 6b [2] 0c 44 }

  condition:
    any of them
}