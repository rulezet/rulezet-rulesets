rule TTP_XOR_QUAD_CurrentVersionRun_240d {
  strings:
    $key_240d = { 77 62 [2] 53 6c [2] 78 40 [2] 56 62 [2] 42 79 [2] 4d 63 [2] 53 7e [2] 51 7f [2] 4a 79 [2] 56 7e [2] 4a 51 }

  condition:
    any of them
}