rule TTP_XOR_QUAD_CurrentVersionRun_6b12 {
  strings:
    $key_6b12 = { 38 7d [2] 1c 73 [2] 37 5f [2] 19 7d [2] 0d 66 [2] 02 7c [2] 1c 61 [2] 1e 60 [2] 05 66 [2] 19 61 [2] 05 4e }

  condition:
    any of them
}