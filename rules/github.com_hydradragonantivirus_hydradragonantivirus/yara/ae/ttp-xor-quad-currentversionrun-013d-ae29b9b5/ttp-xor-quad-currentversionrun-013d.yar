rule TTP_XOR_QUAD_CurrentVersionRun_013d {
  strings:
    $key_013d = { 52 52 [2] 76 5c [2] 5d 70 [2] 73 52 [2] 67 49 [2] 68 53 [2] 76 4e [2] 74 4f [2] 6f 49 [2] 73 4e [2] 6f 61 }

  condition:
    any of them
}