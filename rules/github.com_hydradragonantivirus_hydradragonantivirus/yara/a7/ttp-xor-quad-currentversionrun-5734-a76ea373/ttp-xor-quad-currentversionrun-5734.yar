rule TTP_XOR_QUAD_CurrentVersionRun_5734 {
  strings:
    $key_5734 = { 04 5b [2] 20 55 [2] 0b 79 [2] 25 5b [2] 31 40 [2] 3e 5a [2] 20 47 [2] 22 46 [2] 39 40 [2] 25 47 [2] 39 68 }

  condition:
    any of them
}