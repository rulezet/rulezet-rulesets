rule TTP_XOR_QUAD_CurrentVersionRun_0d22 {
  strings:
    $key_0d22 = { 5e 4d [2] 7a 43 [2] 51 6f [2] 7f 4d [2] 6b 56 [2] 64 4c [2] 7a 51 [2] 78 50 [2] 63 56 [2] 7f 51 [2] 63 7e }

  condition:
    any of them
}