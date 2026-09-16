rule TTP_XOR_QUAD_CurrentVersionRun_1222 {
  strings:
    $key_1222 = { 41 4d [2] 65 43 [2] 4e 6f [2] 60 4d [2] 74 56 [2] 7b 4c [2] 65 51 [2] 67 50 [2] 7c 56 [2] 60 51 [2] 7c 7e }

  condition:
    any of them
}