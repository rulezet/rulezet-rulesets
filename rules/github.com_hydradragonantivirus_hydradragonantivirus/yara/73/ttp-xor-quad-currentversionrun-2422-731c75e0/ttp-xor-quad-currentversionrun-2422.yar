rule TTP_XOR_QUAD_CurrentVersionRun_2422 {
  strings:
    $key_2422 = { 77 4d [2] 53 43 [2] 78 6f [2] 56 4d [2] 42 56 [2] 4d 4c [2] 53 51 [2] 51 50 [2] 4a 56 [2] 56 51 [2] 4a 7e }

  condition:
    any of them
}