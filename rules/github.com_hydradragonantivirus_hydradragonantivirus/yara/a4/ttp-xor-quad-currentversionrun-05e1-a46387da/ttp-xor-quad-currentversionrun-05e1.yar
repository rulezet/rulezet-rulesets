rule TTP_XOR_QUAD_CurrentVersionRun_05e1 {
  strings:
    $key_05e1 = { 56 8e [2] 72 80 [2] 59 ac [2] 77 8e [2] 63 95 [2] 6c 8f [2] 72 92 [2] 70 93 [2] 6b 95 [2] 77 92 [2] 6b bd }

  condition:
    any of them
}