rule TTP_XOR_QUAD_CurrentVersionRun_2669 {
  strings:
    $key_2669 = { 75 06 [2] 51 08 [2] 7a 24 [2] 54 06 [2] 40 1d [2] 4f 07 [2] 51 1a [2] 53 1b [2] 48 1d [2] 54 1a [2] 48 35 }

  condition:
    any of them
}