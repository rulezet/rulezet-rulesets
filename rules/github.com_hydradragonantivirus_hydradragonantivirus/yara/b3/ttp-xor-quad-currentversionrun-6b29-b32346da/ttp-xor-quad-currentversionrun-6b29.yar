rule TTP_XOR_QUAD_CurrentVersionRun_6b29 {
  strings:
    $key_6b29 = { 38 46 [2] 1c 48 [2] 37 64 [2] 19 46 [2] 0d 5d [2] 02 47 [2] 1c 5a [2] 1e 5b [2] 05 5d [2] 19 5a [2] 05 75 }

  condition:
    any of them
}