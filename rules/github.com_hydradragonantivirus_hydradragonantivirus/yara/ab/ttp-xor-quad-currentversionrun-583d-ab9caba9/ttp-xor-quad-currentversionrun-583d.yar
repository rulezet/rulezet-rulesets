rule TTP_XOR_QUAD_CurrentVersionRun_583d {
  strings:
    $key_583d = { 0b 52 [2] 2f 5c [2] 04 70 [2] 2a 52 [2] 3e 49 [2] 31 53 [2] 2f 4e [2] 2d 4f [2] 36 49 [2] 2a 4e [2] 36 61 }

  condition:
    any of them
}