rule TTP_XOR_QUAD_CurrentVersionRun_1a4a {
  strings:
    $key_1a4a = { 49 25 [2] 6d 2b [2] 46 07 [2] 68 25 [2] 7c 3e [2] 73 24 [2] 6d 39 [2] 6f 38 [2] 74 3e [2] 68 39 [2] 74 16 }

  condition:
    any of them
}