rule TTP_XOR_QUAD_CurrentVersionRun_061e {
  strings:
    $key_061e = { 55 71 [2] 71 7f [2] 5a 53 [2] 74 71 [2] 60 6a [2] 6f 70 [2] 71 6d [2] 73 6c [2] 68 6a [2] 74 6d [2] 68 42 }

  condition:
    any of them
}