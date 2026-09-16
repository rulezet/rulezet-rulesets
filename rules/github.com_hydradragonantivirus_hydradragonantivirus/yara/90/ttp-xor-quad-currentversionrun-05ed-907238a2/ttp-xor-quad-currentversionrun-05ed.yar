rule TTP_XOR_QUAD_CurrentVersionRun_05ed {
  strings:
    $key_05ed = { 56 82 [2] 72 8c [2] 59 a0 [2] 77 82 [2] 63 99 [2] 6c 83 [2] 72 9e [2] 70 9f [2] 6b 99 [2] 77 9e [2] 6b b1 }

  condition:
    any of them
}