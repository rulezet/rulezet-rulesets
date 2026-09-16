rule TTP_XOR_QUAD_CurrentVersionRun_2432 {
  strings:
    $key_2432 = { 77 5d [2] 53 53 [2] 78 7f [2] 56 5d [2] 42 46 [2] 4d 5c [2] 53 41 [2] 51 40 [2] 4a 46 [2] 56 41 [2] 4a 6e }

  condition:
    any of them
}