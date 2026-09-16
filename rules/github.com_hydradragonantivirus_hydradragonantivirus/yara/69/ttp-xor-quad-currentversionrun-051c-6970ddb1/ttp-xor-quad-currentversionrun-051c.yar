rule TTP_XOR_QUAD_CurrentVersionRun_051c {
  strings:
    $key_051c = { 56 73 [2] 72 7d [2] 59 51 [2] 77 73 [2] 63 68 [2] 6c 72 [2] 72 6f [2] 70 6e [2] 6b 68 [2] 77 6f [2] 6b 40 }

  condition:
    any of them
}