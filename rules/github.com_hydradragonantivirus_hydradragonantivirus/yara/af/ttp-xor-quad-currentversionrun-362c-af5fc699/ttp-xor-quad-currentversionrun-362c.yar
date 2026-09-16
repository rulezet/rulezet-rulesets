rule TTP_XOR_QUAD_CurrentVersionRun_362c {
  strings:
    $key_362c = { 65 43 [2] 41 4d [2] 6a 61 [2] 44 43 [2] 50 58 [2] 5f 42 [2] 41 5f [2] 43 5e [2] 58 58 [2] 44 5f [2] 58 70 }

  condition:
    any of them
}