rule TTP_XOR_QUAD_CurrentVersionRun_3b22 {
  strings:
    $key_3b22 = { 68 4d [2] 4c 43 [2] 67 6f [2] 49 4d [2] 5d 56 [2] 52 4c [2] 4c 51 [2] 4e 50 [2] 55 56 [2] 49 51 [2] 55 7e }

  condition:
    any of them
}