rule TTP_XOR_QUAD_CurrentVersionRun_3332 {
  strings:
    $key_3332 = { 60 5d [2] 44 53 [2] 6f 7f [2] 41 5d [2] 55 46 [2] 5a 5c [2] 44 41 [2] 46 40 [2] 5d 46 [2] 41 41 [2] 5d 6e }

  condition:
    any of them
}