rule TTP_XOR_QUAD_CurrentVersionRun_151e {
  strings:
    $key_151e = { 46 71 [2] 62 7f [2] 49 53 [2] 67 71 [2] 73 6a [2] 7c 70 [2] 62 6d [2] 60 6c [2] 7b 6a [2] 67 6d [2] 7b 42 }

  condition:
    any of them
}