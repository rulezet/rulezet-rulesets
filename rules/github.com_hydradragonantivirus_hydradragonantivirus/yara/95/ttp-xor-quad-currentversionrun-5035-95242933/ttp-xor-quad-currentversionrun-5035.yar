rule TTP_XOR_QUAD_CurrentVersionRun_5035 {
  strings:
    $key_5035 = { 03 5a [2] 27 54 [2] 0c 78 [2] 22 5a [2] 36 41 [2] 39 5b [2] 27 46 [2] 25 47 [2] 3e 41 [2] 22 46 [2] 3e 69 }

  condition:
    any of them
}