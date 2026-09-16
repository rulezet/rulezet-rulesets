rule TTP_XOR_QUAD_CurrentVersionRun_e522 {
  strings:
    $key_e522 = { b6 4d [2] 92 43 [2] b9 6f [2] 97 4d [2] 83 56 [2] 8c 4c [2] 92 51 [2] 90 50 [2] 8b 56 [2] 97 51 [2] 8b 7e }

  condition:
    any of them
}