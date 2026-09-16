rule TTP_XOR_QUAD_CurrentVersionRun_0914 {
  strings:
    $key_0914 = { 5a 7b [2] 7e 75 [2] 55 59 [2] 7b 7b [2] 6f 60 [2] 60 7a [2] 7e 67 [2] 7c 66 [2] 67 60 [2] 7b 67 [2] 67 48 }

  condition:
    any of them
}