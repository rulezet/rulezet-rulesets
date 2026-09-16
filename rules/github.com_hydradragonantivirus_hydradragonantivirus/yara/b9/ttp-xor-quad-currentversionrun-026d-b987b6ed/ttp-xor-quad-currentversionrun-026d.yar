rule TTP_XOR_QUAD_CurrentVersionRun_026d {
  strings:
    $key_026d = { 51 02 [2] 75 0c [2] 5e 20 [2] 70 02 [2] 64 19 [2] 6b 03 [2] 75 1e [2] 77 1f [2] 6c 19 [2] 70 1e [2] 6c 31 }

  condition:
    any of them
}