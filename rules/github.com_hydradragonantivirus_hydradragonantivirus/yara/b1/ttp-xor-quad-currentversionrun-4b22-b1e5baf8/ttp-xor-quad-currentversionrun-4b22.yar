rule TTP_XOR_QUAD_CurrentVersionRun_4b22 {
  strings:
    $key_4b22 = { 18 4d [2] 3c 43 [2] 17 6f [2] 39 4d [2] 2d 56 [2] 22 4c [2] 3c 51 [2] 3e 50 [2] 25 56 [2] 39 51 [2] 25 7e }

  condition:
    any of them
}