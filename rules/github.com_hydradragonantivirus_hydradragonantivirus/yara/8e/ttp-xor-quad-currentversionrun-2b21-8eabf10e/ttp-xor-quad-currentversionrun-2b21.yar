rule TTP_XOR_QUAD_CurrentVersionRun_2b21 {
  strings:
    $key_2b21 = { 78 4e [2] 5c 40 [2] 77 6c [2] 59 4e [2] 4d 55 [2] 42 4f [2] 5c 52 [2] 5e 53 [2] 45 55 [2] 59 52 [2] 45 7d }

  condition:
    any of them
}