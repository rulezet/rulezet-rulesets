rule TTP_XOR_QUAD_CurrentVersionRun_3c08 {
  strings:
    $key_3c08 = { 6f 67 [2] 4b 69 [2] 60 45 [2] 4e 67 [2] 5a 7c [2] 55 66 [2] 4b 7b [2] 49 7a [2] 52 7c [2] 4e 7b [2] 52 54 }

  condition:
    any of them
}