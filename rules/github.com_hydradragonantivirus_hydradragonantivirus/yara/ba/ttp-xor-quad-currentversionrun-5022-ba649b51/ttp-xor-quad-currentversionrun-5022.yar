rule TTP_XOR_QUAD_CurrentVersionRun_5022 {
  strings:
    $key_5022 = { 03 4d [2] 27 43 [2] 0c 6f [2] 22 4d [2] 36 56 [2] 39 4c [2] 27 51 [2] 25 50 [2] 3e 56 [2] 22 51 [2] 3e 7e }

  condition:
    any of them
}