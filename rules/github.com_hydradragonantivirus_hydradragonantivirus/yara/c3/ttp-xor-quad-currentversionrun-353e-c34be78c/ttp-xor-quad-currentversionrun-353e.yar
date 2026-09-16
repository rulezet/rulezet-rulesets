rule TTP_XOR_QUAD_CurrentVersionRun_353e {
  strings:
    $key_353e = { 66 51 [2] 42 5f [2] 69 73 [2] 47 51 [2] 53 4a [2] 5c 50 [2] 42 4d [2] 40 4c [2] 5b 4a [2] 47 4d [2] 5b 62 }

  condition:
    any of them
}