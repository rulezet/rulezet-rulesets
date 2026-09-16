rule TTP_XOR_QUAD_CurrentVersionRun_19ce {
  strings:
    $key_19ce = { 4a a1 [2] 6e af [2] 45 83 [2] 6b a1 [2] 7f ba [2] 70 a0 [2] 6e bd [2] 6c bc [2] 77 ba [2] 6b bd [2] 77 92 }

  condition:
    any of them
}