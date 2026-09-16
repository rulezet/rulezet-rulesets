rule TTP_XOR_QUAD_CurrentVersionRun_1411 {
  strings:
    $key_1411 = { 47 7e [2] 63 70 [2] 48 5c [2] 66 7e [2] 72 65 [2] 7d 7f [2] 63 62 [2] 61 63 [2] 7a 65 [2] 66 62 [2] 7a 4d }

  condition:
    any of them
}