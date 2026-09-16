rule TTP_XOR_QUAD_CurrentVersionRun_0214 {
  strings:
    $key_0214 = { 51 7b [2] 75 75 [2] 5e 59 [2] 70 7b [2] 64 60 [2] 6b 7a [2] 75 67 [2] 77 66 [2] 6c 60 [2] 70 67 [2] 6c 48 }

  condition:
    any of them
}