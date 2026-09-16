rule TTP_XOR_QUAD_CurrentVersionRun_0d10 {
  strings:
    $key_0d10 = { 5e 7f [2] 7a 71 [2] 51 5d [2] 7f 7f [2] 6b 64 [2] 64 7e [2] 7a 63 [2] 78 62 [2] 63 64 [2] 7f 63 [2] 63 4c }

  condition:
    any of them
}