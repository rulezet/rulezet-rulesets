rule TTP_XOR_QUAD_CurrentVersionRun_2235 {
  strings:
    $key_2235 = { 71 5a [2] 55 54 [2] 7e 78 [2] 50 5a [2] 44 41 [2] 4b 5b [2] 55 46 [2] 57 47 [2] 4c 41 [2] 50 46 [2] 4c 69 }

  condition:
    any of them
}