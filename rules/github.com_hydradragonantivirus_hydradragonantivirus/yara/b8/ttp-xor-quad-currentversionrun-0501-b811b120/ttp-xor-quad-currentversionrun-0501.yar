rule TTP_XOR_QUAD_CurrentVersionRun_0501 {
  strings:
    $key_0501 = { 56 6e [2] 72 60 [2] 59 4c [2] 77 6e [2] 63 75 [2] 6c 6f [2] 72 72 [2] 70 73 [2] 6b 75 [2] 77 72 [2] 6b 5d }

  condition:
    any of them
}