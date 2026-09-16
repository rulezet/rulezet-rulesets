rule TTP_XOR_QUAD_CurrentVersionRun_7a30 {
  strings:
    $key_7a30 = { 29 5f [2] 0d 51 [2] 26 7d [2] 08 5f [2] 1c 44 [2] 13 5e [2] 0d 43 [2] 0f 42 [2] 14 44 [2] 08 43 [2] 14 6c }

  condition:
    any of them
}