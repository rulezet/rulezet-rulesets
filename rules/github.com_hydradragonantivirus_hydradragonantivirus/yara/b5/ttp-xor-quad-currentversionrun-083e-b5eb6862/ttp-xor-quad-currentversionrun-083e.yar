rule TTP_XOR_QUAD_CurrentVersionRun_083e {
  strings:
    $key_083e = { 5b 51 [2] 7f 5f [2] 54 73 [2] 7a 51 [2] 6e 4a [2] 61 50 [2] 7f 4d [2] 7d 4c [2] 66 4a [2] 7a 4d [2] 66 62 }

  condition:
    any of them
}