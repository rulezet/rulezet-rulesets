rule TTP_XOR_QUAD_CurrentVersionRun_3908 {
  strings:
    $key_3908 = { 6a 67 [2] 4e 69 [2] 65 45 [2] 4b 67 [2] 5f 7c [2] 50 66 [2] 4e 7b [2] 4c 7a [2] 57 7c [2] 4b 7b [2] 57 54 }

  condition:
    any of them
}