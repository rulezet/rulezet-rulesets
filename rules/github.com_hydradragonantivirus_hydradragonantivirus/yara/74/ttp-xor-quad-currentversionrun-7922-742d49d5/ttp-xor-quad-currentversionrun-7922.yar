rule TTP_XOR_QUAD_CurrentVersionRun_7922 {
  strings:
    $key_7922 = { 2a 4d [2] 0e 43 [2] 25 6f [2] 0b 4d [2] 1f 56 [2] 10 4c [2] 0e 51 [2] 0c 50 [2] 17 56 [2] 0b 51 [2] 17 7e }

  condition:
    any of them
}