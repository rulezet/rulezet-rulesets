rule TTP_XOR_QUAD_CurrentVersionRun_3a3c {
  strings:
    $key_3a3c = { 69 53 [2] 4d 5d [2] 66 71 [2] 48 53 [2] 5c 48 [2] 53 52 [2] 4d 4f [2] 4f 4e [2] 54 48 [2] 48 4f [2] 54 60 }

  condition:
    any of them
}