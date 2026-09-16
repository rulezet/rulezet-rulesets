rule TTP_XOR_QUAD_CurrentVersionRun_5729 {
  strings:
    $key_5729 = { 04 46 [2] 20 48 [2] 0b 64 [2] 25 46 [2] 31 5d [2] 3e 47 [2] 20 5a [2] 22 5b [2] 39 5d [2] 25 5a [2] 39 75 }

  condition:
    any of them
}