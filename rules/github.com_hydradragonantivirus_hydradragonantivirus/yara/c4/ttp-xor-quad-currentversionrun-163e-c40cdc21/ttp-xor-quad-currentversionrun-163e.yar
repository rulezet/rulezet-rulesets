rule TTP_XOR_QUAD_CurrentVersionRun_163e {
  strings:
    $key_163e = { 45 51 [2] 61 5f [2] 4a 73 [2] 64 51 [2] 70 4a [2] 7f 50 [2] 61 4d [2] 63 4c [2] 78 4a [2] 64 4d [2] 78 62 }

  condition:
    any of them
}