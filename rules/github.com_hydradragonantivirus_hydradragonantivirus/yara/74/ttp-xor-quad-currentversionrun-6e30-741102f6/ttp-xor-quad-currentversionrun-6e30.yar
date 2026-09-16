rule TTP_XOR_QUAD_CurrentVersionRun_6e30 {
  strings:
    $key_6e30 = { 3d 5f [2] 19 51 [2] 32 7d [2] 1c 5f [2] 08 44 [2] 07 5e [2] 19 43 [2] 1b 42 [2] 00 44 [2] 1c 43 [2] 00 6c }

  condition:
    any of them
}