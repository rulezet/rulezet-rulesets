rule TTP_XOR_QUAD_CurrentVersionRun_6c08 {
  strings:
    $key_6c08 = { 3f 67 [2] 1b 69 [2] 30 45 [2] 1e 67 [2] 0a 7c [2] 05 66 [2] 1b 7b [2] 19 7a [2] 02 7c [2] 1e 7b [2] 02 54 }

  condition:
    any of them
}