rule TTP_XOR_QUAD_CurrentVersionRun_0122 {
  strings:
    $key_0122 = { 52 4d [2] 76 43 [2] 5d 6f [2] 73 4d [2] 67 56 [2] 68 4c [2] 76 51 [2] 74 50 [2] 6f 56 [2] 73 51 [2] 6f 7e }

  condition:
    any of them
}