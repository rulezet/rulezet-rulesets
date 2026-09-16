rule TTP_XOR_QUAD_CurrentVersionRun_6a00 {
  strings:
    $key_6a00 = { 39 6f [2] 1d 61 [2] 36 4d [2] 18 6f [2] 0c 74 [2] 03 6e [2] 1d 73 [2] 1f 72 [2] 04 74 [2] 18 73 [2] 04 5c }

  condition:
    any of them
}