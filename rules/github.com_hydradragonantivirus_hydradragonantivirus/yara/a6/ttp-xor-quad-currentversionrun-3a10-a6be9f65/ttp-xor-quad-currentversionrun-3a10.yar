rule TTP_XOR_QUAD_CurrentVersionRun_3a10 {
  strings:
    $key_3a10 = { 69 7f [2] 4d 71 [2] 66 5d [2] 48 7f [2] 5c 64 [2] 53 7e [2] 4d 63 [2] 4f 62 [2] 54 64 [2] 48 63 [2] 54 4c }

  condition:
    any of them
}