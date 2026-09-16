rule TTP_XOR_QUAD_CurrentVersionRun_013c {
  strings:
    $key_013c = { 52 53 [2] 76 5d [2] 5d 71 [2] 73 53 [2] 67 48 [2] 68 52 [2] 76 4f [2] 74 4e [2] 6f 48 [2] 73 4f [2] 6f 60 }

  condition:
    any of them
}