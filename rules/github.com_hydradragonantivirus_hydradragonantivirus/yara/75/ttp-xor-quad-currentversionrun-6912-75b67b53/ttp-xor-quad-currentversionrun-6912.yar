rule TTP_XOR_QUAD_CurrentVersionRun_6912 {
  strings:
    $key_6912 = { 3a 7d [2] 1e 73 [2] 35 5f [2] 1b 7d [2] 0f 66 [2] 00 7c [2] 1e 61 [2] 1c 60 [2] 07 66 [2] 1b 61 [2] 07 4e }

  condition:
    any of them
}