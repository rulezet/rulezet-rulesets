rule TTP_XOR_QUAD_CurrentVersionRun_6208 {
  strings:
    $key_6208 = { 31 67 [2] 15 69 [2] 3e 45 [2] 10 67 [2] 04 7c [2] 0b 66 [2] 15 7b [2] 17 7a [2] 0c 7c [2] 10 7b [2] 0c 54 }

  condition:
    any of them
}