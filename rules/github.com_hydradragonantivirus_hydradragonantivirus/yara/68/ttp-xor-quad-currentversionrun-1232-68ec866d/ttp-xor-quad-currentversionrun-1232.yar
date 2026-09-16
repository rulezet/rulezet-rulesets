rule TTP_XOR_QUAD_CurrentVersionRun_1232 {
  strings:
    $key_1232 = { 41 5d [2] 65 53 [2] 4e 7f [2] 60 5d [2] 74 46 [2] 7b 5c [2] 65 41 [2] 67 40 [2] 7c 46 [2] 60 41 [2] 7c 6e }

  condition:
    any of them
}