rule TTP_XOR_QUAD_CurrentVersionRun_3a6d {
  strings:
    $key_3a6d = { 69 02 [2] 4d 0c [2] 66 20 [2] 48 02 [2] 5c 19 [2] 53 03 [2] 4d 1e [2] 4f 1f [2] 54 19 [2] 48 1e [2] 54 31 }

  condition:
    any of them
}