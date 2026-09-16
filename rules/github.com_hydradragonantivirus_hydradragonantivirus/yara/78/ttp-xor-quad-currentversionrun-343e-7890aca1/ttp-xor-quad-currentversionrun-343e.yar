rule TTP_XOR_QUAD_CurrentVersionRun_343e {
  strings:
    $key_343e = { 67 51 [2] 43 5f [2] 68 73 [2] 46 51 [2] 52 4a [2] 5d 50 [2] 43 4d [2] 41 4c [2] 5a 4a [2] 46 4d [2] 5a 62 }

  condition:
    any of them
}