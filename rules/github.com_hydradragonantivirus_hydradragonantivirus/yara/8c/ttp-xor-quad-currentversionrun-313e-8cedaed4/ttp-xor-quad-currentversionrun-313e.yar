rule TTP_XOR_QUAD_CurrentVersionRun_313e {
  strings:
    $key_313e = { 62 51 [2] 46 5f [2] 6d 73 [2] 43 51 [2] 57 4a [2] 58 50 [2] 46 4d [2] 44 4c [2] 5f 4a [2] 43 4d [2] 5f 62 }

  condition:
    any of them
}