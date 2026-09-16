rule TTP_XOR_QUAD_CurrentVersionRun_6a12 {
  strings:
    $key_6a12 = { 39 7d [2] 1d 73 [2] 36 5f [2] 18 7d [2] 0c 66 [2] 03 7c [2] 1d 61 [2] 1f 60 [2] 04 66 [2] 18 61 [2] 04 4e }

  condition:
    any of them
}