rule TTP_XOR_QUAD_CurrentVersionRun_0234 {
  strings:
    $key_0234 = { 51 5b [2] 75 55 [2] 5e 79 [2] 70 5b [2] 64 40 [2] 6b 5a [2] 75 47 [2] 77 46 [2] 6c 40 [2] 70 47 [2] 6c 68 }

  condition:
    any of them
}