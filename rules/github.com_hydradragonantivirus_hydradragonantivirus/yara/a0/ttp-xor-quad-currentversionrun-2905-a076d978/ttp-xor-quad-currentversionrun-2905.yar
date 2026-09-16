rule TTP_XOR_QUAD_CurrentVersionRun_2905 {
  strings:
    $key_2905 = { 7a 6a [2] 5e 64 [2] 75 48 [2] 5b 6a [2] 4f 71 [2] 40 6b [2] 5e 76 [2] 5c 77 [2] 47 71 [2] 5b 76 [2] 47 59 }

  condition:
    any of them
}