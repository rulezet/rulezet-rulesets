rule TTP_XOR_QUAD_CurrentVersionRun_0500 {
  strings:
    $key_0500 = { 56 6f [2] 72 61 [2] 59 4d [2] 77 6f [2] 63 74 [2] 6c 6e [2] 72 73 [2] 70 72 [2] 6b 74 [2] 77 73 [2] 6b 5c }

  condition:
    any of them
}