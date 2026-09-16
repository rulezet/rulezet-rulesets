rule TTP_XOR_QUAD_CurrentVersionRun_0d3b {
  strings:
    $key_0d3b = { 5e 54 [2] 7a 5a [2] 51 76 [2] 7f 54 [2] 6b 4f [2] 64 55 [2] 7a 48 [2] 78 49 [2] 63 4f [2] 7f 48 [2] 63 67 }

  condition:
    any of them
}