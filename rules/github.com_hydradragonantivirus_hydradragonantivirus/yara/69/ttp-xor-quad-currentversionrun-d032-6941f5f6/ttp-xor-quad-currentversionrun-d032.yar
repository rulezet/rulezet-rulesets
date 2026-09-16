rule TTP_XOR_QUAD_CurrentVersionRun_d032 {
  strings:
    $key_d032 = { 83 5d [2] a7 53 [2] 8c 7f [2] a2 5d [2] b6 46 [2] b9 5c [2] a7 41 [2] a5 40 [2] be 46 [2] a2 41 [2] be 6e }

  condition:
    any of them
}