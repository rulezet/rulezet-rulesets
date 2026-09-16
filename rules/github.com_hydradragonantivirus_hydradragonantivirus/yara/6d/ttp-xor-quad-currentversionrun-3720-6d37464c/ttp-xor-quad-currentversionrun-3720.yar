rule TTP_XOR_QUAD_CurrentVersionRun_3720 {
  strings:
    $key_3720 = { 64 4f [2] 40 41 [2] 6b 6d [2] 45 4f [2] 51 54 [2] 5e 4e [2] 40 53 [2] 42 52 [2] 59 54 [2] 45 53 [2] 59 7c }

  condition:
    any of them
}