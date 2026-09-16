rule TTP_XOR_QUAD_CurrentVersionRun_372c {
  strings:
    $key_372c = { 64 43 [2] 40 4d [2] 6b 61 [2] 45 43 [2] 51 58 [2] 5e 42 [2] 40 5f [2] 42 5e [2] 59 58 [2] 45 5f [2] 59 70 }

  condition:
    any of them
}