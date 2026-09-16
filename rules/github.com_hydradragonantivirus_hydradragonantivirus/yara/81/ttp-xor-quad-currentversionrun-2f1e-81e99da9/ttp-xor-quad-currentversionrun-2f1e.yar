rule TTP_XOR_QUAD_CurrentVersionRun_2f1e {
  strings:
    $key_2f1e = { 7c 71 [2] 58 7f [2] 73 53 [2] 5d 71 [2] 49 6a [2] 46 70 [2] 58 6d [2] 5a 6c [2] 41 6a [2] 5d 6d [2] 41 42 }

  condition:
    any of them
}