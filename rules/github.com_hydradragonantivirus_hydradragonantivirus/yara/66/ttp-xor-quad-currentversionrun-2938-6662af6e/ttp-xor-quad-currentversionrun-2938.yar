rule TTP_XOR_QUAD_CurrentVersionRun_2938 {
  strings:
    $key_2938 = { 7a 57 [2] 5e 59 [2] 75 75 [2] 5b 57 [2] 4f 4c [2] 40 56 [2] 5e 4b [2] 5c 4a [2] 47 4c [2] 5b 4b [2] 47 64 }

  condition:
    any of them
}