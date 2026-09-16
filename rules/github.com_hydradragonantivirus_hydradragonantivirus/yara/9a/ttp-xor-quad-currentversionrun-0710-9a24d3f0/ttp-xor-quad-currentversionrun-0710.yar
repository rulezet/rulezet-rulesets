rule TTP_XOR_QUAD_CurrentVersionRun_0710 {
  strings:
    $key_0710 = { 54 7f [2] 70 71 [2] 5b 5d [2] 75 7f [2] 61 64 [2] 6e 7e [2] 70 63 [2] 72 62 [2] 69 64 [2] 75 63 [2] 69 4c }

  condition:
    any of them
}