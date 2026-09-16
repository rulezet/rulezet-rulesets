rule TTP_XOR_QUAD_CurrentVersionRun_2939 {
  strings:
    $key_2939 = { 7a 56 [2] 5e 58 [2] 75 74 [2] 5b 56 [2] 4f 4d [2] 40 57 [2] 5e 4a [2] 5c 4b [2] 47 4d [2] 5b 4a [2] 47 65 }

  condition:
    any of them
}