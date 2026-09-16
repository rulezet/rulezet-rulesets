rule TTP_XOR_QUAD_CurrentVersionRun_026f {
  strings:
    $key_026f = { 51 00 [2] 75 0e [2] 5e 22 [2] 70 00 [2] 64 1b [2] 6b 01 [2] 75 1c [2] 77 1d [2] 6c 1b [2] 70 1c [2] 6c 33 }

  condition:
    any of them
}