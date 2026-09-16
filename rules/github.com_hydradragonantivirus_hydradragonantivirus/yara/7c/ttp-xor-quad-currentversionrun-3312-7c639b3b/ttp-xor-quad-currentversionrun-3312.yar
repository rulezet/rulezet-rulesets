rule TTP_XOR_QUAD_CurrentVersionRun_3312 {
  strings:
    $key_3312 = { 60 7d [2] 44 73 [2] 6f 5f [2] 41 7d [2] 55 66 [2] 5a 7c [2] 44 61 [2] 46 60 [2] 5d 66 [2] 41 61 [2] 5d 4e }

  condition:
    any of them
}