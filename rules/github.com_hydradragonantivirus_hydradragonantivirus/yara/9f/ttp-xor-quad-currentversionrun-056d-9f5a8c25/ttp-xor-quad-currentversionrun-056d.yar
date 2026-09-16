rule TTP_XOR_QUAD_CurrentVersionRun_056d {
  strings:
    $key_056d = { 56 02 [2] 72 0c [2] 59 20 [2] 77 02 [2] 63 19 [2] 6c 03 [2] 72 1e [2] 70 1f [2] 6b 19 [2] 77 1e [2] 6b 31 }

  condition:
    any of them
}