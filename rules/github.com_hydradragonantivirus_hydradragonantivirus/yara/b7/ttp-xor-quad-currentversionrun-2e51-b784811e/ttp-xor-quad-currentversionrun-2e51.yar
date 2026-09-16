rule TTP_XOR_QUAD_CurrentVersionRun_2e51 {
  strings:
    $key_2e51 = { 7d 3e [2] 59 30 [2] 72 1c [2] 5c 3e [2] 48 25 [2] 47 3f [2] 59 22 [2] 5b 23 [2] 40 25 [2] 5c 22 [2] 40 0d }

  condition:
    any of them
}