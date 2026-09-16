rule TTP_XOR_QUAD_CurrentVersionRun_6a30 {
  strings:
    $key_6a30 = { 39 5f [2] 1d 51 [2] 36 7d [2] 18 5f [2] 0c 44 [2] 03 5e [2] 1d 43 [2] 1f 42 [2] 04 44 [2] 18 43 [2] 04 6c }

  condition:
    any of them
}