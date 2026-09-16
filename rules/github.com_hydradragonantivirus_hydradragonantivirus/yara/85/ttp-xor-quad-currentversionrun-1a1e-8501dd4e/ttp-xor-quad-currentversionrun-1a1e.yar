rule TTP_XOR_QUAD_CurrentVersionRun_1a1e {
  strings:
    $key_1a1e = { 49 71 [2] 6d 7f [2] 46 53 [2] 68 71 [2] 7c 6a [2] 73 70 [2] 6d 6d [2] 6f 6c [2] 74 6a [2] 68 6d [2] 74 42 }

  condition:
    any of them
}