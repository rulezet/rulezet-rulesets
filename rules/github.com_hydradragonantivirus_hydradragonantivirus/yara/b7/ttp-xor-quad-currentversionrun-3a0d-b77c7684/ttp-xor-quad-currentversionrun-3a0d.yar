rule TTP_XOR_QUAD_CurrentVersionRun_3a0d {
  strings:
    $key_3a0d = { 69 62 [2] 4d 6c [2] 66 40 [2] 48 62 [2] 5c 79 [2] 53 63 [2] 4d 7e [2] 4f 7f [2] 54 79 [2] 48 7e [2] 54 51 }

  condition:
    any of them
}