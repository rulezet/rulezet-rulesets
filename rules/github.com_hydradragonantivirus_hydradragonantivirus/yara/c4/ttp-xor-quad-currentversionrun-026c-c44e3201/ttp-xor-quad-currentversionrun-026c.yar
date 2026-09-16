rule TTP_XOR_QUAD_CurrentVersionRun_026c {
  strings:
    $key_026c = { 51 03 [2] 75 0d [2] 5e 21 [2] 70 03 [2] 64 18 [2] 6b 02 [2] 75 1f [2] 77 1e [2] 6c 18 [2] 70 1f [2] 6c 30 }

  condition:
    any of them
}