rule TTP_XOR_QUAD_CurrentVersionRun_3219 {
  strings:
    $key_3219 = { 61 76 [2] 45 78 [2] 6e 54 [2] 40 76 [2] 54 6d [2] 5b 77 [2] 45 6a [2] 47 6b [2] 5c 6d [2] 40 6a [2] 5c 45 }

  condition:
    any of them
}