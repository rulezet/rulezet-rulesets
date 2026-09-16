rule TTP_XOR_QUAD_CurrentVersionRun_180c {
  strings:
    $key_180c = { 4b 63 [2] 6f 6d [2] 44 41 [2] 6a 63 [2] 7e 78 [2] 71 62 [2] 6f 7f [2] 6d 7e [2] 76 78 [2] 6a 7f [2] 76 50 }

  condition:
    any of them
}