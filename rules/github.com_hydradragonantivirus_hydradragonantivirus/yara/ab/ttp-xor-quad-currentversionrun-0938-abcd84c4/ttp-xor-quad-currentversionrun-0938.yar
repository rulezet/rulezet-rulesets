rule TTP_XOR_QUAD_CurrentVersionRun_0938 {
  strings:
    $key_0938 = { 5a 57 [2] 7e 59 [2] 55 75 [2] 7b 57 [2] 6f 4c [2] 60 56 [2] 7e 4b [2] 7c 4a [2] 67 4c [2] 7b 4b [2] 67 64 }

  condition:
    any of them
}