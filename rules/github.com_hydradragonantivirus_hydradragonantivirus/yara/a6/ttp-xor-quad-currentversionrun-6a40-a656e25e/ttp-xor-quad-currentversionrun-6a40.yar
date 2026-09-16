rule TTP_XOR_QUAD_CurrentVersionRun_6a40 {
  strings:
    $key_6a40 = { 39 2f [2] 1d 21 [2] 36 0d [2] 18 2f [2] 0c 34 [2] 03 2e [2] 1d 33 [2] 1f 32 [2] 04 34 [2] 18 33 [2] 04 1c }

  condition:
    any of them
}