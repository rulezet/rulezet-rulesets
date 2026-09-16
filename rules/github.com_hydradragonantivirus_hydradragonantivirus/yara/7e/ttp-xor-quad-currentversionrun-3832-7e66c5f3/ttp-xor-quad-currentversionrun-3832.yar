rule TTP_XOR_QUAD_CurrentVersionRun_3832 {
  strings:
    $key_3832 = { 6b 5d [2] 4f 53 [2] 64 7f [2] 4a 5d [2] 5e 46 [2] 51 5c [2] 4f 41 [2] 4d 40 [2] 56 46 [2] 4a 41 [2] 56 6e }

  condition:
    any of them
}