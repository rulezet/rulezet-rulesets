rule TTP_XOR_QUAD_CurrentVersionRun_0d11 {
  strings:
    $key_0d11 = { 5e 7e [2] 7a 70 [2] 51 5c [2] 7f 7e [2] 6b 65 [2] 64 7f [2] 7a 62 [2] 78 63 [2] 63 65 [2] 7f 62 [2] 63 4d }

  condition:
    any of them
}