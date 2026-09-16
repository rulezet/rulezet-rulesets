rule TTP_XOR_QUAD_CurrentVersionRun_6b30 {
  strings:
    $key_6b30 = { 38 5f [2] 1c 51 [2] 37 7d [2] 19 5f [2] 0d 44 [2] 02 5e [2] 1c 43 [2] 1e 42 [2] 05 44 [2] 19 43 [2] 05 6c }

  condition:
    any of them
}