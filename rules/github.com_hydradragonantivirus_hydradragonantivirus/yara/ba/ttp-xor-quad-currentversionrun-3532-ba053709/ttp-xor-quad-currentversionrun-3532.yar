rule TTP_XOR_QUAD_CurrentVersionRun_3532 {
  strings:
    $key_3532 = { 66 5d [2] 42 53 [2] 69 7f [2] 47 5d [2] 53 46 [2] 5c 5c [2] 42 41 [2] 40 40 [2] 5b 46 [2] 47 41 [2] 5b 6e }

  condition:
    any of them
}