rule TTP_XOR_QUAD_CurrentVersionRun_010d {
  strings:
    $key_010d = { 52 62 [2] 76 6c [2] 5d 40 [2] 73 62 [2] 67 79 [2] 68 63 [2] 76 7e [2] 74 7f [2] 6f 79 [2] 73 7e [2] 6f 51 }

  condition:
    any of them
}