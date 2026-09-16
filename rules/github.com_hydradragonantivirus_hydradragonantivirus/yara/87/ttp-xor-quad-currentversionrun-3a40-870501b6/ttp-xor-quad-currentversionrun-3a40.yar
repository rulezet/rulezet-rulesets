rule TTP_XOR_QUAD_CurrentVersionRun_3a40 {
  strings:
    $key_3a40 = { 69 2f [2] 4d 21 [2] 66 0d [2] 48 2f [2] 5c 34 [2] 53 2e [2] 4d 33 [2] 4f 32 [2] 54 34 [2] 48 33 [2] 54 1c }

  condition:
    any of them
}