rule TTP_XOR_QUAD_CurrentVersionRun_2005 {
  strings:
    $key_2005 = { 73 6a [2] 57 64 [2] 7c 48 [2] 52 6a [2] 46 71 [2] 49 6b [2] 57 76 [2] 55 77 [2] 4e 71 [2] 52 76 [2] 4e 59 }

  condition:
    any of them
}