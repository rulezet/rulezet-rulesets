rule TTP_XOR_QUAD_CurrentVersionRun_e508 {
  strings:
    $key_e508 = { b6 67 [2] 92 69 [2] b9 45 [2] 97 67 [2] 83 7c [2] 8c 66 [2] 92 7b [2] 90 7a [2] 8b 7c [2] 97 7b [2] 8b 54 }

  condition:
    any of them
}