rule TTP_XOR_QUAD_CurrentVersionRun_2714 {
  strings:
    $key_2714 = { 74 7b [2] 50 75 [2] 7b 59 [2] 55 7b [2] 41 60 [2] 4e 7a [2] 50 67 [2] 52 66 [2] 49 60 [2] 55 67 [2] 49 48 }

  condition:
    any of them
}