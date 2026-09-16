rule TTP_XOR_QUAD_CurrentVersionRun_1672 {
  strings:
    $key_1672 = { 45 1d [2] 61 13 [2] 4a 3f [2] 64 1d [2] 70 06 [2] 7f 1c [2] 61 01 [2] 63 00 [2] 78 06 [2] 64 01 [2] 78 2e }

  condition:
    any of them
}