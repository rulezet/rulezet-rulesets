rule TTP_XOR_QUAD_CurrentVersionRun_3032 {
  strings:
    $key_3032 = { 63 5d [2] 47 53 [2] 6c 7f [2] 42 5d [2] 56 46 [2] 59 5c [2] 47 41 [2] 45 40 [2] 5e 46 [2] 42 41 [2] 5e 6e }

  condition:
    any of them
}