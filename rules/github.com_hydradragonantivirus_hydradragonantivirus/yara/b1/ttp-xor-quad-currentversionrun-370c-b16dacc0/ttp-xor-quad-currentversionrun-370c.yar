rule TTP_XOR_QUAD_CurrentVersionRun_370c {
  strings:
    $key_370c = { 64 63 [2] 40 6d [2] 6b 41 [2] 45 63 [2] 51 78 [2] 5e 62 [2] 40 7f [2] 42 7e [2] 59 78 [2] 45 7f [2] 59 50 }

  condition:
    any of them
}