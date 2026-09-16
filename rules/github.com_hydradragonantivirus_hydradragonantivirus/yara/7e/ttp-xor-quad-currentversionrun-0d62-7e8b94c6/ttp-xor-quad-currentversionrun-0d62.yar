rule TTP_XOR_QUAD_CurrentVersionRun_0d62 {
  strings:
    $key_0d62 = { 5e 0d [2] 7a 03 [2] 51 2f [2] 7f 0d [2] 6b 16 [2] 64 0c [2] 7a 11 [2] 78 10 [2] 63 16 [2] 7f 11 [2] 63 3e }

  condition:
    any of them
}