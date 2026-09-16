rule TTP_XOR_QUAD_CurrentVersionRun_3214 {
  strings:
    $key_3214 = { 61 7b [2] 45 75 [2] 6e 59 [2] 40 7b [2] 54 60 [2] 5b 7a [2] 45 67 [2] 47 66 [2] 5c 60 [2] 40 67 [2] 5c 48 }

  condition:
    any of them
}