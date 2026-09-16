rule TTP_XOR_QUAD_CurrentVersionRun_2935 {
  strings:
    $key_2935 = { 7a 5a [2] 5e 54 [2] 75 78 [2] 5b 5a [2] 4f 41 [2] 40 5b [2] 5e 46 [2] 5c 47 [2] 47 41 [2] 5b 46 [2] 47 69 }

  condition:
    any of them
}