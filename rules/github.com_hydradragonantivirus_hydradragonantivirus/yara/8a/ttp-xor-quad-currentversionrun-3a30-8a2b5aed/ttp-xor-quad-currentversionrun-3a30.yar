rule TTP_XOR_QUAD_CurrentVersionRun_3a30 {
  strings:
    $key_3a30 = { 69 5f [2] 4d 51 [2] 66 7d [2] 48 5f [2] 5c 44 [2] 53 5e [2] 4d 43 [2] 4f 42 [2] 54 44 [2] 48 43 [2] 54 6c }

  condition:
    any of them
}