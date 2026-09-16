rule TTP_XOR_QUAD_CurrentVersionRun_663c {
  strings:
    $key_663c = { 35 53 [2] 11 5d [2] 3a 71 [2] 14 53 [2] 00 48 [2] 0f 52 [2] 11 4f [2] 13 4e [2] 08 48 [2] 14 4f [2] 08 60 }

  condition:
    any of them
}