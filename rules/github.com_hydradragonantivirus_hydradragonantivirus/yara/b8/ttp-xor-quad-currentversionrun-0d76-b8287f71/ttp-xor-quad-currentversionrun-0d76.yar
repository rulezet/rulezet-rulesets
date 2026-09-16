rule TTP_XOR_QUAD_CurrentVersionRun_0d76 {
  strings:
    $key_0d76 = { 5e 19 [2] 7a 17 [2] 51 3b [2] 7f 19 [2] 6b 02 [2] 64 18 [2] 7a 05 [2] 78 04 [2] 63 02 [2] 7f 05 [2] 63 2a }

  condition:
    any of them
}