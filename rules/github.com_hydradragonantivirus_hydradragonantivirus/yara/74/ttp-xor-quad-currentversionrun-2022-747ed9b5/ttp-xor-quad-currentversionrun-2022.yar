rule TTP_XOR_QUAD_CurrentVersionRun_2022 {
  strings:
    $key_2022 = { 73 4d [2] 57 43 [2] 7c 6f [2] 52 4d [2] 46 56 [2] 49 4c [2] 57 51 [2] 55 50 [2] 4e 56 [2] 52 51 [2] 4e 7e }

  condition:
    any of them
}