rule TTP_XOR_QUAD_CurrentVersionRun_167d {
  strings:
    $key_167d = { 45 12 [2] 61 1c [2] 4a 30 [2] 64 12 [2] 70 09 [2] 7f 13 [2] 61 0e [2] 63 0f [2] 78 09 [2] 64 0e [2] 78 21 }

  condition:
    any of them
}