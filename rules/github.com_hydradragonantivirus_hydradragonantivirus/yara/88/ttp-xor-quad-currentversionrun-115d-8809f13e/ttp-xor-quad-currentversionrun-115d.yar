rule TTP_XOR_QUAD_CurrentVersionRun_115d {
  strings:
    $key_115d = { 42 32 [2] 66 3c [2] 4d 10 [2] 63 32 [2] 77 29 [2] 78 33 [2] 66 2e [2] 64 2f [2] 7f 29 [2] 63 2e [2] 7f 01 }

  condition:
    any of them
}