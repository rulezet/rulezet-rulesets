rule TTP_XOR_QUAD_CurrentVersionRun_3c14 {
  strings:
    $key_3c14 = { 6f 7b [2] 4b 75 [2] 60 59 [2] 4e 7b [2] 5a 60 [2] 55 7a [2] 4b 67 [2] 49 66 [2] 52 60 [2] 4e 67 [2] 52 48 }

  condition:
    any of them
}