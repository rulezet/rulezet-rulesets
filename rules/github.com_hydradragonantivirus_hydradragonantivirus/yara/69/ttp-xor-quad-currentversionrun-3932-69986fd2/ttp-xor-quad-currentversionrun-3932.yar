rule TTP_XOR_QUAD_CurrentVersionRun_3932 {
  strings:
    $key_3932 = { 6a 5d [2] 4e 53 [2] 65 7f [2] 4b 5d [2] 5f 46 [2] 50 5c [2] 4e 41 [2] 4c 40 [2] 57 46 [2] 4b 41 [2] 57 6e }

  condition:
    any of them
}