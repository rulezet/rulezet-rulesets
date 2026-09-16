rule TTP_XOR_QUAD_CurrentVersionRun_3a32 {
  strings:
    $key_3a32 = { 69 5d [2] 4d 53 [2] 66 7f [2] 48 5d [2] 5c 46 [2] 53 5c [2] 4d 41 [2] 4f 40 [2] 54 46 [2] 48 41 [2] 54 6e }

  condition:
    any of them
}