rule TTP_XOR_QUAD_CurrentVersionRun_2302 {
  strings:
    $key_2302 = { 70 6d [2] 54 63 [2] 7f 4f [2] 51 6d [2] 45 76 [2] 4a 6c [2] 54 71 [2] 56 70 [2] 4d 76 [2] 51 71 [2] 4d 5e }

  condition:
    any of them
}