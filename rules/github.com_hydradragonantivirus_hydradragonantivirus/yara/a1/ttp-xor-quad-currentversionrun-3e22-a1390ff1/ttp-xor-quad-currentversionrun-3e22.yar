rule TTP_XOR_QUAD_CurrentVersionRun_3e22 {
  strings:
    $key_3e22 = { 6d 4d [2] 49 43 [2] 62 6f [2] 4c 4d [2] 58 56 [2] 57 4c [2] 49 51 [2] 4b 50 [2] 50 56 [2] 4c 51 [2] 50 7e }

  condition:
    any of them
}