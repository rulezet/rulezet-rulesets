rule TTP_XOR_QUAD_CurrentVersionRun_0020 {
  strings:
    $key_0020 = { 53 4f [2] 77 41 [2] 5c 6d [2] 72 4f [2] 66 54 [2] 69 4e [2] 77 53 [2] 75 52 [2] 6e 54 [2] 72 53 [2] 6e 7c }

  condition:
    any of them
}