rule TTP_XOR_QUAD_CurrentVersionRun_3422 {
  strings:
    $key_3422 = { 67 4d [2] 43 43 [2] 68 6f [2] 46 4d [2] 52 56 [2] 5d 4c [2] 43 51 [2] 41 50 [2] 5a 56 [2] 46 51 [2] 5a 7e }

  condition:
    any of them
}