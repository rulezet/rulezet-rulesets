rule TTP_XOR_QUAD_CurrentVersionRun_6b11 {
  strings:
    $key_6b11 = { 38 7e [2] 1c 70 [2] 37 5c [2] 19 7e [2] 0d 65 [2] 02 7f [2] 1c 62 [2] 1e 63 [2] 05 65 [2] 19 62 [2] 05 4d }

  condition:
    any of them
}