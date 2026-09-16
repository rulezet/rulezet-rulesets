rule TTP_XOR_QUAD_CurrentVersionRun_052c {
  strings:
    $key_052c = { 56 43 [2] 72 4d [2] 59 61 [2] 77 43 [2] 63 58 [2] 6c 42 [2] 72 5f [2] 70 5e [2] 6b 58 [2] 77 5f [2] 6b 70 }

  condition:
    any of them
}