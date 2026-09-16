rule TTP_XOR_QUAD_CurrentVersionRun_3821 {
  strings:
    $key_3821 = { 6b 4e [2] 4f 40 [2] 64 6c [2] 4a 4e [2] 5e 55 [2] 51 4f [2] 4f 52 [2] 4d 53 [2] 56 55 [2] 4a 52 [2] 56 7d }

  condition:
    any of them
}