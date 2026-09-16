rule TTP_XOR_QUAD_CurrentVersionRun_3929 {
  strings:
    $key_3929 = { 6a 46 [2] 4e 48 [2] 65 64 [2] 4b 46 [2] 5f 5d [2] 50 47 [2] 4e 5a [2] 4c 5b [2] 57 5d [2] 4b 5a [2] 57 75 }

  condition:
    any of them
}