rule TTP_XOR_QUAD_CurrentVersionRun_4e12 {
  strings:
    $key_4e12 = { 1d 7d [2] 39 73 [2] 12 5f [2] 3c 7d [2] 28 66 [2] 27 7c [2] 39 61 [2] 3b 60 [2] 20 66 [2] 3c 61 [2] 20 4e }

  condition:
    any of them
}