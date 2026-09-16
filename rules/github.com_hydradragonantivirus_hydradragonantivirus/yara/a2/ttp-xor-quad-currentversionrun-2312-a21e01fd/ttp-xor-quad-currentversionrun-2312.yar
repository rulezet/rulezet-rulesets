rule TTP_XOR_QUAD_CurrentVersionRun_2312 {
  strings:
    $key_2312 = { 70 7d [2] 54 73 [2] 7f 5f [2] 51 7d [2] 45 66 [2] 4a 7c [2] 54 61 [2] 56 60 [2] 4d 66 [2] 51 61 [2] 4d 4e }

  condition:
    any of them
}