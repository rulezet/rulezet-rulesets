rule TTP_XOR_QUAD_CurrentVersionRun_3872 {
  strings:
    $key_3872 = { 6b 1d [2] 4f 13 [2] 64 3f [2] 4a 1d [2] 5e 06 [2] 51 1c [2] 4f 01 [2] 4d 00 [2] 56 06 [2] 4a 01 [2] 56 2e }

  condition:
    any of them
}