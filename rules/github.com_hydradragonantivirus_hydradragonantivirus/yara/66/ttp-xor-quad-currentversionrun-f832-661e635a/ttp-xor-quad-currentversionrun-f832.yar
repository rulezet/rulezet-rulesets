rule TTP_XOR_QUAD_CurrentVersionRun_f832 {
  strings:
    $key_f832 = { ab 5d [2] 8f 53 [2] a4 7f [2] 8a 5d [2] 9e 46 [2] 91 5c [2] 8f 41 [2] 8d 40 [2] 96 46 [2] 8a 41 [2] 96 6e }

  condition:
    any of them
}